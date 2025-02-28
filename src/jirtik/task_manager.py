import logging
from typing import Dict, List, Optional, Type
from urllib.parse import parse_qs, urlparse
import requests
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from .config_manager import ConfigManager
from .providers.base import IssueProvider
from .providers import AVAILABLE_PROVIDERS

logging.basicConfig(level=logging.INFO)


class AuthCodeHandler(BaseHTTPRequestHandler):
    auth_code = None

    def do_GET(self):
        logging.info("Received GET request")
        # Parse the authorization code from the callback URL
        query_components = parse_qs(urlparse(self.path).query)
        AuthCodeHandler.auth_code = query_components.get('code', [None])[0]
        logging.info("Authorization code: %s", AuthCodeHandler.auth_code)

        # Send a response to the browser
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        response = b"<html><body><h1>Authorization successful!</h1><p>You can close this window now.</p></body></html>"
        self.wfile.write(response)

    def log_message(self, fmt, *args):
        # Suppress server logs
        return


class TaskManager:
    def __init__(self):
        self.config = ConfigManager()
        self._access_token = None
        self.redirect_uri = "http://localhost:8080"
        self.auth_url = "https://ticktick.com/oauth/authorize"
        self.token_url = "https://ticktick.com/oauth/token"
        self.api_base_url = "https://api.ticktick.com/open/v1"

        # Initialize config directory for providers
        self.config_dir = self.config.config_dir

        # Initialize provider instances
        self.providers: List[Type[IssueProvider]] = AVAILABLE_PROVIDERS
        logging.info("TaskManager initialized with providers: %s", [p.__name__ for p in self.providers])

    def _get_provider_for_url(self, url: str) -> Optional[IssueProvider]:
        """Find the appropriate provider for a given URL."""
        for provider_class in self.providers:
            if provider_class.can_handle_url(url):
                return provider_class(self.config_dir)
        return None

    def _get_ticktick_token(self) -> str:
        """Get or refresh TickTick access token."""
        # First try to get token from config
        if not self._access_token:
            self._access_token = self.config.get_config("ticktick_access_token")

        if self._access_token:
            return self._access_token

        # If no token in config, get a new one
        logging.info("Getting new TickTick access token")
        token = self._obtain_new_token()
        # Save the new token to config
        self.config.set_config("ticktick_access_token", token)
        return token

    def _obtain_new_token(self) -> str:
        """Obtain a new access token through OAuth flow."""
        client_id = self.config.get_config("ticktick_client_id")
        client_secret = self.config.get_config("ticktick_client_secret")

        if not all([client_id, client_secret]):
            logging.error("TickTick credentials not found in configuration")
            raise ValueError(
                "TickTick credentials not configured. Please run:\n"
                "  jirtik --configure ticktick_client_id YOUR_CLIENT_ID\n"
                "  jirtik --configure ticktick_client_secret YOUR_CLIENT_SECRET"
            )

        # Start HTTP server
        server = HTTPServer(('localhost', 8080), AuthCodeHandler)
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        try:
            # Open browser for authorization
            auth_params = {
                "response_type": "code",
                "scope": "tasks:write",
                "client_id": client_id,
                "redirect_uri": self.redirect_uri
            }

            auth_url = f"{self.auth_url}?{'&'.join(f'{k}={v}' for k, v in auth_params.items())}"

            logging.info("Opening browser for authorization: %s", auth_url)
            webbrowser.open(auth_url)

            # Wait for the authorization code
            while AuthCodeHandler.auth_code is None:
                logging.info("Waiting for authorization code...")
                threading.Event().wait(1)

            auth_code = AuthCodeHandler.auth_code
            logging.info("Authorization code received")

            # Exchange auth code for access token
            token_data = {
                "grant_type": "authorization_code",
                "code": auth_code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": self.redirect_uri
            }

            response = requests.post(self.token_url, data=token_data)
            if response.status_code != 200:
                logging.error("Failed to get access token: %d", response.status_code)
                logging.error("Response: %s", response.text)
                raise Exception("Failed to get TickTick access token")

            response_json = response.json()
            if "access_token" not in response_json:
                logging.error("Access token not found in response: %s", response_json)
                raise Exception("Access token not found in TickTick response")

            self._access_token = response_json["access_token"]
            return self._access_token

        finally:
            # Clean up
            server.shutdown()
            server.server_close()
            AuthCodeHandler.auth_code = None

    def _make_authenticated_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make an authenticated request with token renewal logic."""
        headers = kwargs.get('headers', {})
        headers['Authorization'] = f"Bearer {self._get_ticktick_token()}"
        kwargs['headers'] = headers

        response = requests.request(method, url, **kwargs)

        # If request failed due to authentication
        if response.status_code in (401, 403):
            logging.info("Token expired, attempting to renew...")
            # Clear stored token
            self._access_token = None
            self.config.set_config("ticktick_access_token", None)

            # Get new token and retry request
            headers['Authorization'] = f"Bearer {self._get_ticktick_token()}"
            response = requests.request(method, url, **kwargs)

            # If it still fails, clear token and raise exception
            if response.status_code in (401, 403):
                self._access_token = None
                self.config.set_config("ticktick_access_token", None)
                raise Exception("Failed to authenticate with TickTick after token renewal")

        return response

    def extract_domain_tag(self, url: str) -> str:
        """Extract tag from the domain of a URL using the appropriate provider."""
        provider = self._get_provider_for_url(url)
        if provider:
            return provider.extract_domain_tag(url)

        # Fallback implementation if no provider is found
        logging.info("No provider found for URL, using default domain extraction: %s", url)
        domain = urlparse(url).netloc
        tag = domain.split(".")[0]
        logging.info("Extracted tag: %s", tag)
        return tag

    def get_issue(self, issue_url: str) -> Dict[str, str]:
        """Get issue details from an issue provider."""
        provider = self._get_provider_for_url(issue_url)
        if not provider:
            logging.error("No provider found for URL: %s", issue_url)
            raise ValueError(f"No provider available for URL: {issue_url}")

        return provider.get_issue(issue_url)

    # Keep get_jira_issue for backward compatibility
    def get_jira_issue(self, issue_url: str) -> Dict[str, str]:
        """Get issue details from an issue provider (backward compatibility)."""
        return self.get_issue(issue_url)

    def _get_ticktick_project(self) -> str:
        logging.info("Retrieving TickTick project ID")
        project_id = self.config.get_config("ticktick_project")
        logging.info("TickTick project ID: %s", project_id)
        return project_id

    def create_ticktick_task(
        self,
        title: str,
        description: str,
        tags: List[str],
    ) -> None:
        """
        Creates a TickTick task with the given title, description and tags.

        Args:
            title: The title of the task
            description: The description/content of the task
            tags: List of tags to add to the task
        Raises:
            Exception: If task creation fails
        """
        logging.info("Creating TickTick task with title: %s", title)
        project_id = self._get_ticktick_project()

        task_data = {
            "title": title,
            "content": description,
            "tags": tags,
            "projectId": project_id
        }

        response = self._make_authenticated_request(
            'POST',
            f"{self.api_base_url}/task",
            headers={"Content-Type": "application/json"},
            json=task_data
        )

        if response.status_code not in (200, 201):
            logging.error("Failed to create task: %s", response.status_code)
            raise Exception("Failed to create TickTick task")

        logging.info("TickTick task created successfully")

    def set_provider_config(self, key: str, value: str) -> None:
        """
        Set a configuration value for the appropriate provider.

        Args:
            key: Configuration key (e.g. jira_email, gitea_token)
            value: Configuration value

        Raises:
            ValueError: If the key is not recognized by any provider
        """
        # Find which provider handles this key
        for provider_class in self.providers:
            if key in provider_class.config_keys:
                provider = provider_class(self.config_dir)
                provider.add_credentials(key, value)
                logging.info("Added %s to %s configuration", key, provider_class.__name__)
                return

        # If we get here, no provider recognized the key
        logging.error("No provider found for config key: %s", key)
        provider_keys = []
        for provider_class in self.providers:
            provider_keys.extend(provider_class.config_keys)

        raise ValueError(f"Invalid configuration key: {key}. Expected one of: {', '.join(provider_keys)}")

    def get_all_supported_config_keys(self) -> List[str]:
        """
        Get all configuration keys supported by the registered providers.

        Returns:
            List of supported configuration keys
        """
        keys = []
        for provider_class in self.providers:
            keys.extend(provider_class.config_keys)
        return keys
