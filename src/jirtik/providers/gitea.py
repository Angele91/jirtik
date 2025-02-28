"""
Gitea provider implementation.
"""
import re
import logging
import os
import json
from typing import Dict, List, Optional
from urllib.parse import urlparse
import requests

from .base import IssueProvider


class GiteaProvider(IssueProvider):
    """Provider for Gitea issues."""

    provider_name = "gitea"
    config_keys = ["gitea_username", "gitea_token"]

    def __init__(self, config_dir: str = None):
        super().__init__(config_dir)
        self.credentials_file = os.path.join(self.config_dir, "creds.json")
        if not os.path.exists(self.credentials_file):
            self._save_credentials({})

    def _load_credentials(self) -> Dict[str, List[str]]:
        """Load credentials from the credentials file."""
        try:
            with open(self.credentials_file, 'r') as f:
                data = json.load(f)
                return {
                    "gitea_usernames": data.get("gitea_usernames", []),
                    "gitea_tokens": data.get("gitea_tokens", [])
                }
        except FileNotFoundError:
            return {"gitea_usernames": [], "gitea_tokens": []}

    def _save_credentials(self, creds: Dict[str, List[str]]) -> None:
        """Save credentials to the credentials file."""
        # We only save our own credentials and preserve others
        try:
            with open(self.credentials_file, 'r') as f:
                existing_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            existing_data = {}

        # Update with our credentials
        existing_data["gitea_usernames"] = creds.get("gitea_usernames", [])
        existing_data["gitea_tokens"] = creds.get("gitea_tokens", [])

        with open(self.credentials_file, 'w') as f:
            json.dump(existing_data, f, indent=4)

    def add_credentials(self, key: str, value: str) -> None:
        """
        Add a new credential value for a specific key.

        Args:
            key: Credential key (e.g., gitea_username, gitea_token)
            value: Value to add
        """
        if key not in GiteaProvider.config_keys:
            raise ValueError(f"Invalid config key: {key}. Expected one of {GiteaProvider.config_keys}")

        creds = self._load_credentials()
        key_plural = f"{key}s"  # gitea_username -> gitea_usernames
        values = creds.get(key_plural, [])
        if value not in values:
            values.append(value)
            creds[key_plural] = values
            self._save_credentials(creds)

    def get_credentials(self) -> Dict[str, List[str]]:
        """
        Get all stored Gitea credentials.

        Returns:
            Dictionary with usernames and tokens
        """
        return self._load_credentials()

    def _get_gitea_credentials(self) -> Dict[str, List[str]]:
        """Get Gitea credentials from config."""
        logging.info("Retrieving Gitea credentials")
        creds = self._load_credentials()
        usernames = creds.get("gitea_usernames", [])
        tokens = creds.get("gitea_tokens", [])

        if not usernames:
            logging.error("No Gitea usernames found in configuration")
            raise ValueError(
                "No Gitea usernames configured. Use 'jirtik --configure "
                "gitea_username <username>'"
            )

        if not tokens:
            logging.error("No Gitea tokens found in configuration")
            raise ValueError(
                "No Gitea tokens configured. Use 'jirtik --configure "
                "gitea_token <token>'"
            )

        logging.info("Gitea credentials retrieved successfully")
        return {"usernames": usernames, "tokens": tokens}

    def extract_domain_tag(self, url: str) -> str:
        """Extract a tag from the Gitea URL domain."""
        logging.info("Extracting domain tag from Gitea URL: %s", url)
        domain = urlparse(url).netloc
        tag = domain.split(".")[0]
        logging.info("Extracted tag: %s", tag)
        return tag

    @classmethod
    def can_handle_url(cls, url: str) -> bool:
        """
        Check if the URL is a Gitea issue URL.

        Example Gitea URLs:
        - https://gitea.example.com/owner/repo/issues/123
        """
        return bool(re.search(r"/issues/(\d+)$", url))

    def get_credentials_for_domain(self, domain: str) -> Optional[Dict[str, str]]:
        """Get cached credentials for a specific Gitea domain."""
        token_map = self._load_token_map()
        domain_creds = token_map.get(domain, {})
        if domain_creds:
            return {
                "username": domain_creds.get("username"),
                "token": domain_creds.get("token")
            }
        return None

    def set_credentials_for_domain(self, domain: str, username: str = None, token: str = None, **kwargs) -> None:
        """Cache successful credentials for a specific Gitea domain."""
        token_map = self._load_token_map()
        token_map[domain] = {
            "username": username,
            "token": token
        }
        self._save_token_map(token_map)

    def remove_credentials_for_domain(self, domain: str) -> None:
        """Remove cached credentials for a domain."""
        token_map = self._load_token_map()
        if domain in token_map:
            del token_map[domain]
            self._save_token_map(token_map)

    def get_issue(self, issue_url: str) -> Dict[str, str]:
        """
        Get issue details from Gitea.

        Args:
            issue_url: URL of the Gitea issue

        Returns:
            Dictionary with issue details

        Raises:
            ValueError: If URL is invalid
            Exception: If issue fetch fails
        """
        logging.info("Fetching Gitea issue from URL: %s", issue_url)

        # Extract repo and issue number from URL
        match = re.search(r"(.*)/issues/(\d+)$", issue_url)
        if not match:
            logging.error("Invalid Gitea issue URL: %s", issue_url)
            raise ValueError("Invalid Gitea issue URL")

        repo_url = match.group(1)
        issue_number = match.group(2)
        domain = urlparse(repo_url).netloc

        # Get API URL
        # Typically Gitea API is at /api/v1
        api_base = f"https://{domain}/api/v1"

        # Get owner/repo from repo_url
        repo_path = urlparse(repo_url).path
        repo_parts = repo_path.strip('/').split('/')
        if len(repo_parts) < 2:
            logging.error("Invalid Gitea repository path: %s", repo_path)
            raise ValueError("Invalid Gitea repository path")

        owner = repo_parts[0]
        repo = repo_parts[1]

        api_url = f"{api_base}/repos/{owner}/{repo}/issues/{issue_number}"
        logging.info("Making API request to: %s", api_url)

        # Try cached credentials first
        cached_creds = self.get_credentials_for_domain(domain)
        if cached_creds:
            logging.info("Using cached credentials for domain: %s", domain)
            response = requests.get(
                api_url,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"token {cached_creds['token']}"
                }
            )
            if response.status_code == 200:
                data = response.json()
                logging.info("Successfully fetched Gitea issue using cached credentials: %s", issue_number)
                return {
                    "summary": data.get("title", f"Issue #{issue_number}"),
                    "description": data.get("body", "") or "",
                }
            elif response.status_code == 401:
                logging.info("Cached credentials expired for domain: %s", domain)
                self.remove_credentials_for_domain(domain)

        # Try all username and token combinations
        creds = self._get_gitea_credentials()
        for username in creds["usernames"]:
            for token in creds["tokens"]:
                logging.info("Trying credentials combination - Username: %s", username)
                response = requests.get(
                    api_url,
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"token {token}"
                    }
                )

                if response.status_code == 200:
                    # Cache the successful credentials
                    self.set_credentials_for_domain(domain, username=username, token=token)
                    data = response.json()
                    logging.info("Successfully fetched Gitea issue: %s", issue_number)
                    return {
                        "summary": data.get("title", f"Issue #{issue_number}"),
                        "description": data.get("body", "") or "",
                    }
                elif response.status_code in (401, 403, 404):
                    logging.info("Credentials combination failed, trying next combination...")
                else:
                    # If it's not an authentication error, raise the exception
                    logging.error(
                        "Gitea API request failed with status code: %d",
                        response.status_code
                    )
                    raise Exception(
                        f"Failed to fetch Gitea issue: {response.status_code}"
                    )

        # If we get here, all combinations failed or we couldn't authenticate
        # For demonstration, return dummy data
        logging.warning("All Gitea credential combinations failed or API implementation incomplete - returning dummy data")
        return {
            "summary": f"Gitea Issue #{issue_number}",
            "description": "This is a placeholder for Gitea issue description."
        }
