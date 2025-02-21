import re
import logging
from typing import Dict, List
from urllib.parse import parse_qs, urlparse
import requests
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from .config_manager import ConfigManager

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
        logging.info("TaskManager initialized")

    def _get_jira_credentials(self) -> Dict[str, List[str]]:
        logging.info("Retrieving JIRA credentials")
        emails = self.config.get_jira_emails()
        if not emails:
            logging.error("No JIRA emails found in configuration")
            raise ValueError(
                "No JIRA emails configured. Use 'jirtik --configure "
                "jira_email <email>'"
            )

        tokens = self.config.get_jira_tokens()
        if not tokens:
            logging.error("No JIRA tokens found in configuration")
            raise ValueError(
                "No JIRA tokens configured. Use 'jirtik --configure "
                "jira_token <token>'"
            )

        logging.info("JIRA credentials retrieved successfully")
        return {"emails": emails, "tokens": tokens}

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

    def _extract_domain_tag(self, url: str) -> str:
        logging.info("Extracting domain tag from URL: %s", url)
        domain = urlparse(url).netloc
        tag = domain.split(".")[0]
        logging.info("Extracted tag: %s", tag)
        return tag

    def get_jira_issue(self, issue_url: str) -> Dict[str, str]:
        logging.info("Fetching JIRA issue from URL: %s", issue_url)
        creds = self._get_jira_credentials()

        # Extract issue key and domain from URL
        match = re.search(r"/browse/([A-Z]+-\d+)", issue_url)
        if not match:
            logging.error("Invalid JIRA issue URL: %s", issue_url)
            raise ValueError("Invalid JIRA issue URL")

        issue_key = match.group(1)
        base_url = issue_url.split("/browse/")[0]
        domain = urlparse(base_url).netloc
        api_url = f"{base_url}/rest/api/2/issue/{issue_key}"
        logging.info("Making API request to: %s", api_url)

        # Try cached credentials first
        cached_creds = self.config.get_credentials_for_domain(domain)
        if cached_creds:
            logging.info("Using cached credentials for domain: %s", domain)
            response = requests.get(
                api_url,
                auth=(cached_creds["email"], cached_creds["token"]),
                headers={"Accept": "application/json"},
            )
            if response.status_code == 200:
                data = response.json()
                logging.info("Successfully fetched JIRA issue using cached credentials: %s", issue_key)
                return {
                    "summary": data["fields"]["summary"],
                    "description": data["fields"]["description"] or "",
                }
            elif response.status_code == 401:
                logging.info("Cached credentials expired for domain: %s", domain)
                self.config.remove_credentials_for_domain(domain)

        # Try all email and token combinations
        for email in creds["emails"]:
            for token in creds["tokens"]:
                logging.info("Trying credentials combination - Email: %s", email)
                response = requests.get(
                    api_url,
                    auth=(email, token),
                    headers={"Accept": "application/json"},
                )

                if response.status_code == 200:
                    # Cache the successful credentials
                    self.config.set_credentials_for_domain(domain, email, token)
                    data = response.json()
                    logging.info("Successfully fetched JIRA issue: %s", issue_key)
                    return {
                        "summary": data["fields"]["summary"],
                        "description": data["fields"]["description"] or "",
                    }
                elif response.status_code == 401 or response.status_code == 403 or response.status_code == 404:
                    logging.info("Credentials combination failed, trying next combination...")
                else:
                    # If it's not an authentication error, raise the exception
                    logging.error(
                        "JIRA API request failed with status code: %d",
                        response.status_code
                    )
                    raise Exception(
                        f"Failed to fetch JIRA issue: {response.status_code}"
                    )

                logging.info("Credentials combination failed, trying next combination...")

        # If we get here, all combinations failed
        logging.error("All JIRA credential combinations failed authentication")
        raise Exception("Failed to authenticate with any configured JIRA credentials")

    def _get_ticktick_project(self) -> str:
        logging.info("Retrieving TickTick project ID")
        project_id = self.config.get_config("ticktick_project")
        logging.info("TickTick project ID: %s", project_id)
        return project_id

    def create_ticktick_task(
        self,
        title: str,
        description: str,
        tags: list[str],
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
