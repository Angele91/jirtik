"""
Jira provider implementation.
"""
import re
import logging
import os
import json
from typing import Dict, List, Optional
from urllib.parse import urlparse
import requests

from .base import IssueProvider


class JiraProvider(IssueProvider):
    """Provider for Jira issues."""

    provider_name = "jira"
    config_keys = ["jira_email", "jira_token"]

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
                    "jira_emails": data.get("jira_emails", []),
                    "jira_tokens": data.get("jira_tokens", [])
                }
        except FileNotFoundError:
            return {"jira_emails": [], "jira_tokens": []}

    def _save_credentials(self, creds: Dict[str, List[str]]) -> None:
        """Save credentials to the credentials file."""
        # We only save our own credentials and preserve others
        try:
            with open(self.credentials_file, 'r') as f:
                existing_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            existing_data = {}

        # Update with our credentials
        existing_data["jira_emails"] = creds.get("jira_emails", [])
        existing_data["jira_tokens"] = creds.get("jira_tokens", [])

        with open(self.credentials_file, 'w') as f:
            json.dump(existing_data, f, indent=4)

    def add_credentials(self, key: str, value: str) -> None:
        """
        Add a new credential value for a specific key.

        Args:
            key: Credential key (e.g., jira_email, jira_token)
            value: Value to add
        """
        if key not in JiraProvider.config_keys:
            raise ValueError(f"Invalid config key: {key}. Expected one of {JiraProvider.config_keys}")

        creds = self._load_credentials()
        key_plural = f"{key}s"  # jira_email -> jira_emails
        values = creds.get(key_plural, [])
        if value not in values:
            values.append(value)
            creds[key_plural] = values
            self._save_credentials(creds)

    def get_credentials(self) -> Dict[str, List[str]]:
        """
        Get all stored Jira credentials.

        Returns:
            Dictionary with emails and tokens
        """
        return self._load_credentials()

    def _get_jira_credentials(self) -> Dict[str, List[str]]:
        """Get Jira credentials from config."""
        logging.info("Retrieving JIRA credentials")
        creds = self._load_credentials()
        emails = creds.get("jira_emails", [])
        tokens = creds.get("jira_tokens", [])

        if not emails:
            logging.error("No JIRA emails found in configuration")
            raise ValueError(
                "No JIRA emails configured. Use 'jirtik --configure "
                "jira_email <email>'"
            )

        if not tokens:
            logging.error("No JIRA tokens found in configuration")
            raise ValueError(
                "No JIRA tokens configured. Use 'jirtik --configure "
                "jira_token <token>'"
            )

        logging.info("JIRA credentials retrieved successfully")
        return {"emails": emails, "tokens": tokens}

    def extract_domain_tag(self, url: str) -> str:
        """Extract a tag from the Jira URL domain."""
        logging.info("Extracting domain tag from URL: %s", url)
        domain = urlparse(url).netloc
        tag = domain.split(".")[0]
        logging.info("Extracted tag: %s", tag)
        return tag

    @classmethod
    def can_handle_url(cls, url: str) -> bool:
        """Check if the URL is a JIRA issue URL."""
        return bool(re.search(r"/browse/([A-Z]+-\d+)", url))

    def get_credentials_for_domain(self, domain: str) -> Optional[Dict[str, str]]:
        """Get cached credentials for a specific Jira domain."""
        token_map = self._load_token_map()
        domain_creds = token_map.get(domain, {})
        if domain_creds:
            return {
                "email": domain_creds.get("email"),
                "token": domain_creds.get("token")
            }
        return None

    def set_credentials_for_domain(self, domain: str, email: str = None, token: str = None, **kwargs) -> None:
        """Cache successful credentials for a specific Jira domain."""
        token_map = self._load_token_map()
        token_map[domain] = {
            "email": email,
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
        """Get issue details from JIRA."""
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
        cached_creds = self.get_credentials_for_domain(domain)
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
                self.remove_credentials_for_domain(domain)

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
                    self.set_credentials_for_domain(domain, email=email, token=token)
                    data = response.json()
                    logging.info("Successfully fetched JIRA issue: %s", issue_key)
                    return {
                        "summary": data["fields"]["summary"],
                        "description": data["fields"]["description"] or "",
                    }
                elif response.status_code in (401, 403, 404):
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

        # If we get here, all combinations failed
        logging.error("All JIRA credential combinations failed authentication")
        raise Exception("Failed to authenticate with any configured JIRA credentials")
