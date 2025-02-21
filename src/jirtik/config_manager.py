import json
import os
from pathlib import Path
from typing import Dict, Optional, List


class ConfigManager:
    def __init__(self):
        self.config_dir = os.path.expanduser("~/.jirtik")
        self.config_file = os.path.join(self.config_dir, "creds.json")
        self.token_map_file = os.path.join(self.config_dir, "jira_token_map.json")
        self._ensure_config_dir()

    def _ensure_config_dir(self) -> None:
        Path(self.config_dir).mkdir(parents=True, exist_ok=True)
        if not os.path.exists(self.config_file):
            self._save_config({})
        if not os.path.exists(self.token_map_file):
            self._save_token_map({})

    def _load_config(self) -> Dict[str, str | List[str]]:
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _save_config(self, config: Dict[str, str | List[str]]) -> None:
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=4)

    def _load_token_map(self) -> Dict[str, Dict[str, str]]:
        try:
            with open(self.token_map_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _save_token_map(self, token_map: Dict[str, Dict[str, str]]) -> None:
        with open(self.token_map_file, 'w') as f:
            json.dump(token_map, f, indent=4)

    def set_config(self, key: str, value: str) -> None:
        config = self._load_config()
        if key in ["jira_token", "jira_email"]:
            # For JIRA tokens and emails, store as lists
            key_plural = f"{key}s"  # jira_token -> jira_tokens, jira_email -> jira_emails
            values = config.get(key_plural, [])
            if value not in values:
                values.append(value)
            config[key_plural] = values
        else:
            config[key] = value
        self._save_config(config)

    def get_config(self, key: str) -> Optional[str | List[str]]:
        config = self._load_config()
        if key in ["jira_token", "jira_email"]:
            # Return the first value for backward compatibility
            key_plural = f"{key}s"
            values = config.get(key_plural, [])
            return values[0] if values else None
        return config.get(key)

    def get_jira_tokens(self) -> List[str]:
        """Get all configured JIRA tokens."""
        config = self._load_config()
        return config.get("jira_tokens", [])

    def get_jira_emails(self) -> List[str]:
        """Get all configured JIRA emails."""
        config = self._load_config()
        return config.get("jira_emails", [])

    def get_credentials_for_domain(self, domain: str) -> Optional[Dict[str, str]]:
        """Get the cached credentials for a specific JIRA domain."""
        token_map = self._load_token_map()
        domain_creds = token_map.get(domain, {})
        if domain_creds:
            return {
                "email": domain_creds.get("email"),
                "token": domain_creds.get("token")
            }
        return None

    def set_credentials_for_domain(self, domain: str, email: str, token: str) -> None:
        """Cache successful credentials for a specific JIRA domain."""
        token_map = self._load_token_map()
        token_map[domain] = {
            "email": email,
            "token": token
        }
        self._save_token_map(token_map)

    def remove_credentials_for_domain(self, domain: str) -> None:
        """Remove cached credentials mapping for a domain."""
        token_map = self._load_token_map()
        if domain in token_map:
            del token_map[domain]
            self._save_token_map(token_map)
