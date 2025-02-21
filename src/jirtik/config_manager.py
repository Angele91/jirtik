import json
import os
from pathlib import Path
from typing import Dict, Optional


class ConfigManager:
    def __init__(self):
        self.config_dir = os.path.expanduser("~/.jirtik")
        self.config_file = os.path.join(self.config_dir, "creds.json")
        self._ensure_config_dir()

    def _ensure_config_dir(self) -> None:
        Path(self.config_dir).mkdir(parents=True, exist_ok=True)
        if not os.path.exists(self.config_file):
            self._save_config({})

    def _load_config(self) -> Dict[str, str]:
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _save_config(self, config: Dict[str, str]) -> None:
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=4)

    def set_config(self, key: str, value: str) -> None:
        config = self._load_config()
        config[key] = value
        self._save_config(config)

    def get_config(self, key: str) -> Optional[str]:
        config = self._load_config()
        return config.get(key)
