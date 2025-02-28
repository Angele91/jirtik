"""
Base provider interface for issue providers.
"""
import abc
import os
import json
from pathlib import Path
from typing import Dict, List, Optional, ClassVar


class IssueProvider(abc.ABC):
    """Base abstract class for issue providers like Jira, Gitea, etc."""

    # These should be overridden in provider implementations
    provider_name: ClassVar[str] = "base"  # Used for file naming and display
    config_keys: ClassVar[List[str]] = []  # List of config keys this provider uses

    def __init__(self, config_dir: str = None):
        """
        Initialize the provider with configuration directory.

        Args:
            config_dir: Directory to store configuration files. Default is ~/.jirtik
        """
        self.config_dir = config_dir or os.path.expanduser("~/.jirtik")
        Path(self.config_dir).mkdir(parents=True, exist_ok=True)

        # Provider-specific configuration file
        self.token_map_file = os.path.join(self.config_dir, f"{self.provider_name}_token_map.json")
        if not os.path.exists(self.token_map_file):
            self._save_token_map({})

    def _load_token_map(self) -> Dict[str, Dict[str, str]]:
        """Load the provider-specific token map."""
        try:
            with open(self.token_map_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _save_token_map(self, token_map: Dict[str, Dict[str, str]]) -> None:
        """Save the provider-specific token map."""
        with open(self.token_map_file, 'w') as f:
            json.dump(token_map, f, indent=4)

    @classmethod
    def get_config_keys(cls) -> List[str]:
        """Get the configuration keys used by this provider."""
        return cls.config_keys

    @abc.abstractmethod
    def get_issue(self, issue_url: str) -> Dict[str, str]:
        """
        Retrieve issue details from the provider.

        Args:
            issue_url: URL of the issue

        Returns:
            Dictionary containing issue details (summary, description, etc.)

        Raises:
            ValueError: If the URL is invalid
            Exception: If fetching the issue fails
        """
        pass

    @abc.abstractmethod
    def extract_domain_tag(self, url: str) -> str:
        """
        Extract a tag from the issue URL domain.

        Args:
            url: Issue URL

        Returns:
            Tag string derived from the domain
        """
        pass

    @classmethod
    @abc.abstractmethod
    def can_handle_url(cls, url: str) -> bool:
        """
        Check if this provider can handle the given URL.

        Args:
            url: Issue URL to check

        Returns:
            True if this provider can handle the URL, False otherwise
        """
        pass

    @abc.abstractmethod
    def get_credentials_for_domain(self, domain: str) -> Optional[Dict[str, str]]:
        """
        Get cached credentials for a specific domain.

        Args:
            domain: Domain name

        Returns:
            Dictionary with credentials if found, None otherwise
        """
        pass

    @abc.abstractmethod
    def set_credentials_for_domain(self, domain: str, **credentials) -> None:
        """
        Cache credentials for a specific domain.

        Args:
            domain: Domain name
            **credentials: Provider-specific credential key-value pairs
        """
        pass

    @abc.abstractmethod
    def remove_credentials_for_domain(self, domain: str) -> None:
        """
        Remove cached credentials for a domain.

        Args:
            domain: Domain name to remove credentials for
        """
        pass
