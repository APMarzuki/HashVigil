# core/config_manager.py
import configparser
import os
from pathlib import Path
from typing import Dict, Any

class ConfigManager:
    def __init__(self):
        self.config_dir = Path(__file__).parent.parent / 'config'
        self.config_file = self.config_dir / 'settings.ini'
        self.config = configparser.ConfigParser()
        self.load_config()

    def load_config(self):
        """Load configuration from file"""
        if self.config_file.exists():
            self.config.read(self.config_file)
        else:
            self.create_default_config()

    def create_default_config(self):
        """Create default configuration file"""
        self.config['API_KEYS'] = {
            'virustotal': '',
            'otx': '',
            'abuseipdb': ''
        }
        self.config['SETTINGS'] = {
            'theme': 'dark',
            'cache_duration': '3600',
            'max_concurrent_requests': '5',
            'auto_export': 'false',
            'risk_threshold': '70'
        }
        self.save_config()

    def save_config(self):
        """Save configuration to file"""
        self.config_dir.mkdir(exist_ok=True)
        with open(self.config_file, 'w') as f:
            self.config.write(f)

    def get_api_key(self, service: str) -> str:
        """Get API key for a service"""
        return self.config.get('API_KEYS', service, fallback='')

    def set_api_key(self, service: str, key: str):
        """Set API key for a service"""
        if not self.config.has_section('API_KEYS'):
            self.config.add_section('API_KEYS')
        self.config.set('API_KEYS', service, key)
        self.save_config()

    def get_setting(self, section: str, key: str, fallback: Any = None) -> Any:
        """Get application setting"""
        return self.config.get(section, key, fallback=fallback)

    def set_setting(self, section: str, key: str, value: Any):
        """Set application setting"""
        if not self.config.has_section(section):
            self.config.add_section(section)
        self.config.set(section, key, str(value))
        self.save_config()

    def get_all_settings(self) -> Dict[str, Dict[str, str]]:
        """Get all settings as dictionary"""
        return {section: dict(self.config[section]) for section in self.config.sections()}