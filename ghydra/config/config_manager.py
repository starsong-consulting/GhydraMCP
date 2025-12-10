"""Configuration file management for GhydraMCP CLI."""

import json
import os
import sys
from pathlib import Path
from typing import Optional

from .defaults import GhidraConfig
from ..client.exceptions import GhidraConfigError


class ConfigManager:
    """Manage GhydraMCP CLI configuration file.

    Configuration is stored at ~/.ghydra/config.json
    """

    CONFIG_DIR = Path.home() / ".ghydra"
    CONFIG_FILE = CONFIG_DIR / "config.json"

    @classmethod
    def load(cls, verbose: bool = False) -> GhidraConfig:
        """Load configuration from file or use defaults.

        Args:
            verbose: Print verbose loading messages

        Returns:
            GhidraConfig instance with loaded or default values

        Raises:
            GhidraConfigError: If config file is malformed
        """
        if not cls.CONFIG_FILE.exists():
            if verbose:
                print(f"Config file not found at {cls.CONFIG_FILE}, using defaults", file=sys.stderr)
            return GhidraConfig()

        try:
            with open(cls.CONFIG_FILE, 'r') as f:
                data = json.load(f)

            if verbose:
                print(f"Loaded config from {cls.CONFIG_FILE}", file=sys.stderr)

            # Validate and filter known keys only
            valid_keys = {
                'default_host', 'default_port', 'timeout',
                'use_colors', 'page_output', 'max_pagination'
            }
            filtered_data = {k: v for k, v in data.items() if k in valid_keys}

            return GhidraConfig.from_dict(filtered_data)

        except json.JSONDecodeError as e:
            raise GhidraConfigError(
                f"Invalid JSON in config file {cls.CONFIG_FILE}: {e}"
            ) from e
        except TypeError as e:
            raise GhidraConfigError(
                f"Invalid config data in {cls.CONFIG_FILE}: {e}"
            ) from e
        except Exception as e:
            print(f"Warning: Failed to load config: {e}", file=sys.stderr)
            return GhidraConfig()

    @classmethod
    def save(cls, config: GhidraConfig, verbose: bool = False):
        """Save configuration to file.

        Args:
            config: Configuration to save
            verbose: Print verbose save messages

        Raises:
            GhidraConfigError: If save fails
        """
        try:
            # Create config directory if it doesn't exist
            cls.CONFIG_DIR.mkdir(parents=True, exist_ok=True)

            # Write config file
            with open(cls.CONFIG_FILE, 'w') as f:
                json.dump(config.to_dict(), f, indent=2)

            if verbose:
                print(f"Saved config to {cls.CONFIG_FILE}", file=sys.stderr)

        except (IOError, OSError) as e:
            raise GhidraConfigError(
                f"Failed to save config to {cls.CONFIG_FILE}: {e}"
            ) from e

    @classmethod
    def init_config(cls, force: bool = False) -> bool:
        """Initialize config file with defaults.

        Args:
            force: Overwrite existing config file

        Returns:
            True if config was created/updated, False if exists and not forced

        Raises:
            GhidraConfigError: If initialization fails
        """
        if cls.CONFIG_FILE.exists() and not force:
            return False

        config = GhidraConfig()
        cls.save(config, verbose=True)
        return True

    @classmethod
    def get_config_path(cls) -> Path:
        """Get the configuration file path.

        Returns:
            Path to configuration file
        """
        return cls.CONFIG_FILE
