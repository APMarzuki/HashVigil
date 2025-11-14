class ThreatIntelligenceAggregator:
    def __init__(self):
        self.results = {}

    def add_result(self, source, data):
        """Add results from a specific source"""
        self.results[source] = data

    def calculate_risk_score(self):
        """Calculate overall risk score based on all results"""
        score = 0
        total_weight = 0

        for source, data in self.results.items():
            if 'error' not in data:
                source_score = self._calculate_source_score(source, data)
                weight = self._get_source_weight(source)
                score += source_score * weight
                total_weight += weight

        if total_weight == 0:
            return 0

        return min(100, int(score / total_weight))

    def _calculate_source_score(self, source, data):
        """Calculate risk score for a specific source"""
        if source == 'VirusTotal':
            return self._parse_virustotal_score(data)
        elif source == 'AbuseIPDB':
            return self._parse_abuseipdb_score(data)
        elif source == 'AlienVault OTX':
            return self._parse_otx_score(data)
        return 0

    def _get_source_weight(self, source):
        """Get weight for each source in overall risk calculation"""
        weights = {
            'VirusTotal': 1.0,
            'AbuseIPDB': 0.8,
            'AlienVault OTX': 0.7
        }
        return weights.get(source, 0.5)

    def _parse_virustotal_score(self, data):
        """Parse VirusTotal data to calculate risk score"""
        # We'll implement this after we see the actual API response format
        return 0

    def _parse_abuseipdb_score(self, data):
        """Parse AbuseIPDB data to calculate risk score"""
        # We'll implement this after we see the actual API response format
        return 0

    def _parse_otx_score(self, data):
        """Parse OTX data to calculate risk score"""
        # We'll implement this after we see the actual API response format
        return 0

    def get_consolidated_results(self):
        """Return all results in a consolidated format"""
        return self.results

    def get_summary(self):
        """Get a summary of the analysis"""
        risk_score = self.calculate_risk_score()
        sources_checked = len([src for src in self.results if 'error' not in self.results[src]])

        return {
            'risk_score': risk_score,
            'sources_checked': sources_checked,
            'total_sources': len(self.results)
        }