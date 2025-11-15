from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLineEdit, QPushButton, QTabWidget, QTextEdit,
                             QLabel, QFileDialog, QMessageBox, QProgressBar,
                             QDialog, QMenuBar, QMenu, QAction)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QPalette, QColor
import json
import csv
from datetime import datetime
from core.api_virustotal import VirusTotalAPI
from core.api_otx import OTXAPI
from core.api_abuseipdb import AbuseIPDBAPI
from core.aggregator import ThreatIntelligenceAggregator
from gui.settings_window import SettingsWindow
from core.config_manager import ConfigManager


class AnalysisThread(QThread):
    """Thread for handling API calls to prevent GUI freezing"""
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, input_text):
        super().__init__()
        self.input_text = input_text

    def run(self):
        try:
            aggregator = ThreatIntelligenceAggregator()

            # Determine if input is IP or hash
            if self.is_ip_address(self.input_text):
                results = self.check_ip(self.input_text)
            else:
                results = self.check_hash(self.input_text)

            self.finished.emit(results)
        except Exception as e:
            self.error.emit(str(e))

    def is_ip_address(self, text):
        """Simple check if input is IP address"""
        parts = text.split('.')
        if len(parts) == 4:
            return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
        return False

    def check_hash(self, file_hash):
        """Check file hash against all services"""
        aggregator = ThreatIntelligenceAggregator()

        # VirusTotal
        vt = VirusTotalAPI()
        vt_result = vt.check_hash(file_hash)
        aggregator.add_result('VirusTotal', vt_result)

        # AlienVault OTX
        otx = OTXAPI()
        otx_result = otx.check_hash(file_hash)
        aggregator.add_result('AlienVault OTX', otx_result)

        return aggregator.get_consolidated_results()

    def check_ip(self, ip_address):
        """Check IP address against AbuseIPDB"""
        aggregator = ThreatIntelligenceAggregator()

        # AbuseIPDB
        abuse = AbuseIPDBAPI()
        abuse_result = abuse.check_ip(ip_address)
        aggregator.add_result('AbuseIPDB', abuse_result)

        return aggregator.get_consolidated_results()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.analysis_thread = None
        self.last_results = {}
        self.config = ConfigManager()  # Add config manager
        self.init_ui()
        self.apply_theme()  # Apply theme on startup

    def init_ui(self):
        self.setWindowTitle("HashVigil - Threat Intelligence Analyzer")
        self.setGeometry(100, 100, 1000, 800)

        # Create menu bar first
        self.create_menu_bar()

        # Apply initial theme
        self.apply_theme()

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(10)
        layout.setContentsMargins(15, 15, 15, 15)

        # Title
        title_label = QLabel("🔍 HashVigil - Threat Intelligence Analyzer")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #0078d4; padding: 10px;")

        # Input section
        input_layout = QHBoxLayout()
        input_layout.setSpacing(10)

        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Enter file hash (MD5, SHA256) or IP address...")
        self.input_field.returnPressed.connect(self.analyze)

        self.analyze_btn = QPushButton("🔍 Analyze")
        self.analyze_btn.setObjectName("analyze_btn")
        self.analyze_btn.clicked.connect(self.analyze)

        self.bulk_btn = QPushButton("📁 Bulk Import")
        self.bulk_btn.clicked.connect(self.bulk_import)

        self.clear_btn = QPushButton("🗑️ Clear")
        self.clear_btn.setObjectName("clear_btn")
        self.clear_btn.clicked.connect(self.clear_results)

        self.export_btn = QPushButton("💾 Export Results")
        self.export_btn.setObjectName("export_btn")
        self.export_btn.clicked.connect(self.export_results)

        input_layout.addWidget(QLabel("Input:"))
        input_layout.addWidget(self.input_field, 1)  # Stretch factor 1
        input_layout.addWidget(self.analyze_btn)
        input_layout.addWidget(self.bulk_btn)
        input_layout.addWidget(self.clear_btn)
        input_layout.addWidget(self.export_btn)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedHeight(20)

        # Results area
        results_label = QLabel("Analysis Results:")
        results_label.setStyleSheet("font-weight: bold; font-size: 12px; color: #e1a34e;")

        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)

        # Add to main layout
        layout.addWidget(title_label)
        layout.addLayout(input_layout)
        layout.addWidget(self.progress_bar)
        layout.addWidget(results_label)
        layout.addWidget(self.results_display, 1)  # Stretch factor 1

    def create_menu_bar(self):
        """Create application menu bar"""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu('📁 File')

        settings_action = QAction('⚙️ Settings', self)
        settings_action.triggered.connect(self.open_settings)
        file_menu.addAction(settings_action)

        file_menu.addSeparator()

        exit_action = QAction('🚪 Exit', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # View menu
        view_menu = menubar.addMenu('👀 View')

        self.theme_menu = view_menu.addMenu('🎨 Theme')

        dark_action = QAction('Dark', self)
        dark_action.triggered.connect(lambda: self.change_theme('dark'))
        self.theme_menu.addAction(dark_action)

        light_action = QAction('Light', self)
        light_action.triggered.connect(lambda: self.change_theme('light'))
        self.theme_menu.addAction(light_action)

        # Help menu
        help_menu = menubar.addMenu('❓ Help')

        about_action = QAction('ℹ️ About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def open_settings(self):
        """Open settings dialog"""
        settings_dialog = SettingsWindow(self)
        if settings_dialog.exec_() == QDialog.Accepted:
            # Reload theme if settings were saved
            self.apply_theme()

    def change_theme(self, theme_name):
        """Change application theme"""
        self.config.set_setting('SETTINGS', 'theme', theme_name)
        self.apply_theme()

    def apply_theme(self):
        """Apply current theme from settings"""
        theme = self.config.get_setting('SETTINGS', 'theme', 'dark')

        if theme == 'light':
            self.apply_light_theme()
        else:
            self.apply_dark_theme()

    def apply_dark_theme(self):
        """Apply dark theme stylesheet"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QWidget {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QLineEdit {
                background-color: #3c3c3c;
                color: #ffffff;
                border: 2px solid #555555;
                border-radius: 5px;
                padding: 8px;
                font-size: 12px;
            }
            QLineEdit:focus {
                border-color: #0078d4;
            }
            QPushButton {
                background-color: #0078d4;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 15px;
                font-weight: bold;
                font-size: 11px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
            QPushButton:pressed {
                background-color: #005a9e;
            }
            QPushButton:disabled {
                background-color: #555555;
                color: #888888;
            }
            QPushButton#analyze_btn {
                background-color: #107c10;
            }
            QPushButton#analyze_btn:hover {
                background-color: #0e6b0e;
            }
            QPushButton#export_btn {
                background-color: #e1a34e;
            }
            QPushButton#export_btn:hover {
                background-color: #d1933e;
            }
            QPushButton#clear_btn {
                background-color: #d13438;
            }
            QPushButton#clear_btn:hover {
                background-color: #c12a2e;
            }
            QTextEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #555555;
                border-radius: 5px;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 11px;
                padding: 10px;
            }
            QLabel {
                color: #ffffff;
                font-weight: bold;
            }
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 5px;
                text-align: center;
                color: white;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: #0078d4;
                border-radius: 4px;
            }
            QMenuBar {
                background-color: #2b2b2b;
                color: #ffffff;
                border-bottom: 1px solid #555555;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 5px 10px;
            }
            QMenuBar::item:selected {
                background-color: #0078d4;
                color: white;
            }
            QMenu {
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #555555;
            }
            QMenu::item {
                padding: 5px 20px;
            }
            QMenu::item:selected {
                background-color: #0078d4;
                color: white;
            }
        """)

    def apply_light_theme(self):
        """Apply light theme stylesheet"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
                color: #333333;
            }
            QWidget {
                background-color: #f0f0f0;
                color: #333333;
            }
            QLineEdit {
                background-color: #ffffff;
                color: #333333;
                border: 2px solid #cccccc;
                border-radius: 5px;
                padding: 8px;
                font-size: 12px;
            }
            QLineEdit:focus {
                border-color: #0078d4;
            }
            QPushButton {
                background-color: #0078d4;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 15px;
                font-weight: bold;
                font-size: 11px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
            QPushButton:pressed {
                background-color: #005a9e;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #888888;
            }
            QPushButton#analyze_btn {
                background-color: #107c10;
            }
            QPushButton#analyze_btn:hover {
                background-color: #0e6b0e;
            }
            QPushButton#export_btn {
                background-color: #e1a34e;
            }
            QPushButton#export_btn:hover {
                background-color: #d1933e;
            }
            QPushButton#clear_btn {
                background-color: #d13438;
            }
            QPushButton#clear_btn:hover {
                background-color: #c12a2e;
            }
            QTextEdit {
                background-color: #ffffff;
                color: #333333;
                border: 1px solid #cccccc;
                border-radius: 5px;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 11px;
                padding: 10px;
            }
            QLabel {
                color: #333333;
                font-weight: bold;
            }
            QProgressBar {
                border: 1px solid #cccccc;
                border-radius: 5px;
                text-align: center;
                color: #333333;
                font-weight: bold;
                background-color: #ffffff;
            }
            QProgressBar::chunk {
                background-color: #0078d4;
                border-radius: 4px;
            }
            QMenuBar {
                background-color: #f0f0f0;
                color: #333333;
                border-bottom: 1px solid #cccccc;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 5px 10px;
            }
            QMenuBar::item:selected {
                background-color: #0078d4;
                color: white;
            }
            QMenu {
                background-color: #ffffff;
                color: #333333;
                border: 1px solid #cccccc;
            }
            QMenu::item {
                padding: 5px 20px;
            }
            QMenu::item:selected {
                background-color: #0078d4;
                color: white;
            }
        """)

    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, "About HashVigil",
                          "<h2>HashVigil v2.0</h2>"
                          "<p>Advanced Threat Intelligence Analyzer</p>"
                          "<p>Features:</p>"
                          "<ul>"
                          "<li>Multi-source threat intelligence</li>"
                          "<li>VirusTotal, OTX, AbuseIPDB integration</li>"
                          "<li>Dark/Light theme support</li>"
                          "<li>Bulk analysis capabilities</li>"
                          "<li>Export functionality</li>"
                          "</ul>"
                          "<p>Built with Python and PyQt5</p>")

    def analyze(self):
        input_text = self.input_field.text().strip()
        if not input_text:
            QMessageBox.warning(self, "Input Required", "Please enter a hash or IP address to analyze.")
            return

        # Disable buttons during analysis
        self.analyze_btn.setEnabled(False)
        self.bulk_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.clear_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress

        self.results_display.setText(
            f"🔍 Analyzing: {input_text}\n\nPlease wait while we check threat intelligence sources...")

        # Start analysis in separate thread
        self.analysis_thread = AnalysisThread(input_text)
        self.analysis_thread.finished.connect(self.on_analysis_complete)
        self.analysis_thread.error.connect(self.on_analysis_error)
        self.analysis_thread.start()

    def on_analysis_complete(self, results):
        """Handle completed analysis"""
        self.analyze_btn.setEnabled(True)
        self.bulk_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        self.clear_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

        # Store results for export
        self.last_results = results

        # Format and display results
        formatted_results = self.format_results(results)
        self.results_display.setText(formatted_results)

    def on_analysis_error(self, error_message):
        """Handle analysis errors"""
        self.analyze_btn.setEnabled(True)
        self.bulk_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        self.clear_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

        self.results_display.setText(
            f"❌ Error during analysis:\n{error_message}\n\nPlease check your API keys and internet connection.")

    def format_results(self, results):
        """Format the API results for display"""
        output = "🎯 THREAT INTELLIGENCE RESULTS\n"
        output += "=" * 60 + "\n\n"

        for source, data in results.items():
            output += f"🔍 {source}:\n"
            output += "─" * 50 + "\n"

            if 'error' in data:
                output += f"   ❌ Error: {data['error']}\n"
            elif source == 'VirusTotal':
                output += self._format_virustotal(data)
            elif source == 'AlienVault OTX':
                output += self._format_otx(data)
            elif source == 'AbuseIPDB':
                output += self._format_abuseipdb(data)
            else:
                output += "   ℹ️  Data format not yet implemented\n"

            output += "\n"

        # Add summary
        output += self._generate_summary(results)

        return output

    def _format_virustotal(self, data):
        """Format VirusTotal results"""
        if 'data' not in data or 'data' not in data['data']:
            return "   ❌ No scan data available\n"

        file_data = data['data']['data']
        attributes = file_data.get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})

        formatted = f"   📄 File: {attributes.get('meaningful_name', 'Unknown')}\n"
        formatted += f"   📊 Size: {attributes.get('size', 0):,} bytes\n"
        formatted += f"   🔧 Type: {attributes.get('type_description', 'Unknown')}\n"
        formatted += f"   📅 First Seen: {self._format_timestamp(attributes.get('first_submission_date'))}\n"
        formatted += f"   📅 Last Seen: {self._format_timestamp(attributes.get('last_submission_date'))}\n\n"

        # Detection stats
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        undetected = stats.get('undetected', 0)
        harmless = stats.get('harmless', 0)
        total = malicious + suspicious + undetected + harmless

        if total > 0:
            formatted += f"   🎯 Detection Ratio: {malicious}/{total} ({malicious / total * 100:.1f}% malicious)\n"
        else:
            formatted += "   🎯 Detection Ratio: No data available\n"

        if malicious > 0:
            formatted += f"   ⚠️  MALICIOUS DETECTIONS: {malicious} engines\n"
        elif suspicious > 0:
            formatted += f"   ⚠️  SUSPICIOUS: {suspicious} engines\n"
        else:
            formatted += "   ✅ No malicious detections\n"

        # Reputation
        reputation = attributes.get('reputation', 0)
        if reputation < 0:
            formatted += f"   ⭐ Reputation: {reputation} (Poor)\n"
        elif reputation > 0:
            formatted += f"   ⭐ Reputation: {reputation} (Good)\n"
        else:
            formatted += "   ⭐ Reputation: Neutral\n"

        # Tags
        tags = attributes.get('tags', [])
        if tags:
            formatted += f"   🏷️  Tags: {', '.join(tags[:5])}\n"

        return formatted

    def _format_otx(self, data):
        """Format AlienVault OTX results"""
        if 'data' not in data:
            return "   ❌ No data available\n"

        otx_data = data['data']
        formatted = ""

        # Check if it's a known empty file
        validation = otx_data.get('validation', [])
        for val in validation:
            if val.get('source') == 'empty_file':
                formatted += "   ✅ Known empty file (benign)\n"
                break

        # Pulse count
        pulse_info = otx_data.get('pulse_info', {})
        pulse_count = pulse_info.get('count', 0)

        if pulse_count > 0:
            formatted += f"   ⚠️  Found in {pulse_count} threat intelligence pulses\n"
        else:
            formatted += "   ✅ Not found in any threat intelligence\n"

        # False positive info
        false_positives = otx_data.get('false_positive', [])
        if false_positives:
            formatted += "   📝 Marked as false positive\n"

        return formatted

    def _format_abuseipdb(self, data):
        """Format AbuseIPDB results"""
        if 'data' not in data:
            return "   ❌ No data available\n"

        abuse_data = data['data']
        formatted = ""

        # Basic IP info
        if 'data' in abuse_data:
            ip_data = abuse_data['data']
            formatted += f"   🌐 IP: {ip_data.get('ipAddress', 'Unknown')}\n"
            formatted += f"   🔗 Domain: {ip_data.get('domain', 'Unknown')}\n"
            formatted += f"   🏴 Country: {ip_data.get('countryName', 'Unknown')}\n"
            formatted += f"   💼 ISP: {ip_data.get('isp', 'Unknown')}\n\n"

            # Abuse confidence
            confidence = ip_data.get('abuseConfidenceScore', 0)
            if confidence > 75:
                formatted += f"   🔴 High abuse confidence: {confidence}%\n"
            elif confidence > 25:
                formatted += f"   🟡 Medium abuse confidence: {confidence}%\n"
            else:
                formatted += f"   🟢 Low abuse confidence: {confidence}%\n"

            # Total reports
            total_reports = ip_data.get('totalReports', 0)
            formatted += f"   📊 Total Reports: {total_reports:,}\n"

            # Last reported
            last_reported = ip_data.get('lastReportedAt')
            if last_reported:
                formatted += f"   📅 Last Reported: {last_reported[:10]}\n"

        return formatted

    def _format_timestamp(self, timestamp):
        """Convert Unix timestamp to readable date"""
        if not timestamp:
            return "Unknown"
        from datetime import datetime
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

    def _generate_summary(self, results):
        """Generate a summary of all results"""
        output = "\n" + "=" * 60 + "\n"
        output += "📋 SUMMARY\n"
        output += "=" * 60 + "\n"

        risk_level = "UNKNOWN"
        risk_color = "⚪"
        risk_details = []

        # Analyze VirusTotal
        vt_data = results.get('VirusTotal', {})
        if 'data' in vt_data and 'data' in vt_data['data']:
            stats = vt_data['data']['data'].get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)

            if malicious > 5:
                risk_level = "HIGH"
                risk_color = "🔴"
                risk_details.append(f"{malicious} malicious detections")
            elif malicious > 0:
                risk_level = "MEDIUM"
                risk_color = "🟡"
                risk_details.append(f"{malicious} malicious detections")
            else:
                risk_level = "LOW"
                risk_color = "🟢"
                risk_details.append("No malicious detections")

        # Analyze OTX
        otx_data = results.get('AlienVault OTX', {})
        if 'data' in otx_data:
            pulse_count = otx_data['data'].get('pulse_info', {}).get('count', 0)
            if pulse_count > 10:
                if risk_level != "HIGH":
                    risk_level = "HIGH"
                    risk_color = "🔴"
                risk_details.append(f"Found in {pulse_count} threat pulses")
            elif pulse_count > 0:
                if risk_level not in ["HIGH", "MEDIUM"]:
                    risk_level = "MEDIUM"
                    risk_color = "🟡"
                risk_details.append(f"Found in {pulse_count} threat pulses")

        # Analyze AbuseIPDB
        abuse_data = results.get('AbuseIPDB', {})
        if 'data' in abuse_data and 'data' in abuse_data['data']:
            ip_data = abuse_data['data']['data']
            confidence = ip_data.get('abuseConfidenceScore', 0)
            total_reports = ip_data.get('totalReports', 0)

            if confidence > 75 or total_reports > 50:
                risk_level = "HIGH"
                risk_color = "🔴"
                risk_details.append(f"{confidence}% abuse confidence, {total_reports:,} reports")
            elif confidence > 25 or total_reports > 10:
                if risk_level != "HIGH":
                    risk_level = "MEDIUM"
                    risk_color = "🟡"
                risk_details.append(f"{confidence}% abuse confidence, {total_reports:,} reports")
            else:
                if risk_level == "UNKNOWN":
                    risk_level = "LOW"
                    risk_color = "🟢"
                risk_details.append(f"{confidence}% abuse confidence")

        output += f"Overall Risk: {risk_color} {risk_level}\n"

        if risk_details:
            output += "📝 Reasons: " + ", ".join(risk_details) + "\n"

        # Sources checked
        sources_checked = [src for src in results if 'error' not in results[src]]
        output += f"\n🔍 Sources Checked: {len(sources_checked)}/{len(results)}\n"

        # Recommendations
        output += "\n💡 Recommendations:\n"
        if risk_level == "HIGH":
            output += "• 🚫 BLOCK this indicator immediately\n"
            output += "• 🔍 Investigate related systems\n"
            output += "• 📞 Consider incident response procedures\n"
        elif risk_level == "MEDIUM":
            output += "• 👀 Monitor closely\n"
            output += "• 🔍 Investigate further\n"
            output += "• 🚫 Consider blocking if suspicious activity\n"
        elif risk_level == "LOW":
            output += "• ✅ Likely safe\n"
            output += "• 📊 Continue normal monitoring\n"
        else:
            output += "• ❓ Insufficient data for assessment\n"
            output += "• 🔍 Consider additional investigation\n"

        return output

    def export_results(self):
        """Export results to JSON or CSV"""
        if not self.last_results:
            QMessageBox.warning(self, "No Results", "No results to export. Please analyze something first.")
            return

        file_path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            f"threat_intel_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "JSON Files (*.json);;CSV Files (*.csv)"
        )

        if file_path:
            try:
                if selected_filter == "JSON Files (*.json)":
                    if not file_path.endswith('.json'):
                        file_path += '.json'
                    with open(file_path, 'w') as f:
                        json.dump(self.last_results, f, indent=2)
                    QMessageBox.information(self, "Export Successful", f"Results exported to {file_path}")

                elif selected_filter == "CSV Files (*.csv)":
                    if not file_path.endswith('.csv'):
                        file_path += '.csv'
                    self._export_to_csv(file_path)
                    QMessageBox.information(self, "Export Successful", f"Results exported to {file_path}")

            except Exception as e:
                QMessageBox.critical(self, "Export Failed", f"Failed to export results: {str(e)}")

    def _export_to_csv(self, file_path):
        """Export results to CSV format"""
        with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)

            # Write header
            writer.writerow(['Source', 'Indicator', 'Risk Level', 'Details', 'Timestamp'])

            # Write data
            for source, data in self.last_results.items():
                if 'error' in data:
                    writer.writerow([source, 'Unknown', 'Error', data['error'], ''])
                else:
                    # Extract basic info based on source
                    indicator = 'Unknown'
                    risk = 'Unknown'
                    details = ''

                    if source == 'VirusTotal' and 'data' in data:
                        vt_data = data['data']['data']
                        attrs = vt_data.get('attributes', {})
                        stats = attrs.get('last_analysis_stats', {})
                        malicious = stats.get('malicious', 0)
                        indicator = attrs.get('meaningful_name', 'Unknown File')
                        risk = f"{malicious} malicious detections"
                        details = f"Size: {attrs.get('size', 0)} bytes, Type: {attrs.get('type_description', 'Unknown')}"

                    elif source == 'AbuseIPDB' and 'data' in data:
                        ip_data = data['data']['data']
                        indicator = ip_data.get('ipAddress', 'Unknown IP')
                        confidence = ip_data.get('abuseConfidenceScore', 0)
                        risk = f"{confidence}% abuse confidence"
                        details = f"ISP: {ip_data.get('isp', 'Unknown')}, Reports: {ip_data.get('totalReports', 0)}"

                    elif source == 'AlienVault OTX' and 'data' in data:
                        otx_data = data['data']
                        indicator = otx_data.get('indicator', 'Unknown')
                        pulse_count = otx_data.get('pulse_info', {}).get('count', 0)
                        risk = f"Found in {pulse_count} pulses"
                        details = "AlienVault OTX Analysis"

                    writer.writerow([source, indicator, risk, details, datetime.now().strftime('%Y-%m-%d %H:%M:%S')])

    def bulk_import(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select file with IOCs", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    iocs = [line.strip() for line in file if line.strip() and not line.startswith('#')]

                if iocs:
                    self.bulk_iocs = iocs  # Store for analysis
                    self.current_bulk_index = 0

                    # Show preview and analysis options
                    preview_text = f"📁 Loaded {len(iocs)} IOCs from: {file_path}\n\n"
                    preview_text += "First 5 IOCs:\n" + "\n".join(iocs[:5])
                    if len(iocs) > 5:
                        preview_text += f"\n... and {len(iocs) - 5} more\n\n"

                    preview_text += "\n🔍 Options:\n"
                    preview_text += "• Copy & paste each IOC manually for analysis\n"
                    preview_text += "• Or analyze sequentially (coming in v2.0!)"

                    self.results_display.setText(preview_text)

                    # Optional: Auto-analyze first IOC
                    if iocs:
                        self.input_field.setText(iocs[0])
                        # Uncomment next line to auto-analyze first item:
                        # self.analyze()

                else:
                    self.results_display.setText(
                        "❌ No valid IOCs found in the selected file.\n\nMake sure each IOC is on a separate line.")

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to read file: {str(e)}")

    def clear_results(self):
        self.results_display.clear()
        self.input_field.clear()