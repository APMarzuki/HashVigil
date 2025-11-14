import requests
import configparser
from pathlib import Path


class AbuseIPDBAPI:
    def __init__(self):
        self.load_config()

    def load_config(self):
        config = configparser.ConfigParser()
        config_file = Path(__file__).parent.parent / 'config' / 'settings.ini'
        config.read(config_file)
        self.api_key = config.get('API_KEYS', 'abuseipdb', fallback='')
        self.base_url = 'https://api.abuseipdb.com/api/v2'

    def check_ip(self, ip_address):
        """Check IP address against AbuseIPDB"""
        if not self.api_key:
            return {'error': 'AbuseIPDB API key not configured'}

        headers = {
            'Key': self.api_key,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90
        }

        try:
            response = requests.get(f"{self.base_url}/check", headers=headers, params=params)
            if response.status_code == 200:
                return self.parse_response(response.json())
            else:
                return {'error': f"API returned status {response.status_code}"}
        except Exception as e:
            return {'error': str(e)}

    def parse_response(self, data):
        """Parse AbuseIPDB API response"""
        return {'source': 'AbuseIPDB', 'data': data}