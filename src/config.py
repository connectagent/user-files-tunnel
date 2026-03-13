"""Configuration management."""

import json
import os
import platform
from pathlib import Path




def _get_base_path() -> Path:
    """Get platform-specific base path for app data."""
    system = platform.system()
    if system == 'Windows':
        return Path(os.environ.get('APPDATA', Path.home())) / 'agentic'
    return Path.home() / '.agentic'


BASE_PATH = _get_base_path()



def get_config_path() -> Path:
    """Get config file path."""
    return BASE_PATH / 'user_files.json'


def get_policy_path() -> Path:
    """Get default policy file path (same folder as config)."""
    return BASE_PATH / 'default.policy'


def load_config() -> dict | None:
    """Load saved credentials from config file."""
    config_path = get_config_path()
    if not config_path.exists():
        return None
    try:
        return json.loads(config_path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def save_config(user_id: str, token: str, tunnel_url: str) -> None:
    """Save credentials to config file."""
    config_path = get_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        json.dumps({'user_id': user_id, 'token': token, 'tunnel_url': tunnel_url}, indent=2)
    )


def clear_config() -> None:
    """Delete saved credentials."""
    config_path = get_config_path()
    if config_path.exists():
        config_path.unlink()
