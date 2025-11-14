import requests
import configparser
from pathlib import Path


class OTXAPI:
    def __init__(self):
        self.load_config()

    def load_config(self):
        config = configparser.ConfigParser()
        config_file = Path(__file__).parent.parent / 'config' / 'settings.ini'
        config.read(config_file)
        self.api_key = config.get('API_KEYS', 'otx', fallback='')
        self.base_url = 'https://otx.alienvault.com/api/v1'

    def check_hash(self, file_hash):
        """Check file hash against AlienVault OTX"""
        if not self.api_key:
            return {'error': 'OTX API key not configured'}

        url = f"{self.base_url}/indicators/file/{file_hash}/general"

        try:
            response = requests.get(url)
            if response.status_code == 200:
                return self.parse_response(response.json())
            else:
                return {'error': f"API returned status {response.status_code}"}
        except Exception as e:
            return {'error': str(e)}

    def parse_response(self, data):
        """Parse OTX API response"""
        return {'source': 'AlienVault OTX', 'data': data}