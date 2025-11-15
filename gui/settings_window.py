# gui/settings_window.py
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTabWidget,
                             QWidget, QLineEdit, QLabel, QPushButton,
                             QComboBox, QCheckBox, QSpinBox, QMessageBox,
                             QFormLayout, QGroupBox)
from PyQt5.QtCore import Qt
from core.config_manager import ConfigManager


class SettingsWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.config = ConfigManager()
        self.init_ui()
        self.load_current_settings()

    def init_ui(self):
        self.setWindowTitle("HashVigil - Settings")
        self.setFixedSize(600, 500)
        self.setStyleSheet(self.get_style_sheet())

        layout = QVBoxLayout(self)

        # Create tab widget
        self.tabs = QTabWidget()

        # API Keys Tab
        self.api_tab = self.create_api_tab()
        self.tabs.addTab(self.api_tab, "🔑 API Keys")

        # Appearance Tab
        self.appearance_tab = self.create_appearance_tab()
        self.tabs.addTab(self.appearance_tab, "🎨 Appearance")

        # Behavior Tab
        self.behavior_tab = self.create_behavior_tab()
        self.tabs.addTab(self.behavior_tab, "⚙️ Behavior")

        layout.addWidget(self.tabs)

        # Buttons
        button_layout = QHBoxLayout()

        self.save_btn = QPushButton("💾 Save Settings")
        self.save_btn.clicked.connect(self.save_settings)

        self.cancel_btn = QPushButton("❌ Cancel")
        self.cancel_btn.clicked.connect(self.reject)

        self.test_btn = QPushButton("🔍 Test Connections")
        self.test_btn.clicked.connect(self.test_connections)

        button_layout.addWidget(self.test_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.cancel_btn)
        button_layout.addWidget(self.save_btn)

        layout.addLayout(button_layout)

    def create_api_tab(self):
        widget = QWidget()
        layout = QFormLayout(widget)

        # VirusTotal
        self.vt_key_edit = QLineEdit()
        self.vt_key_edit.setEchoMode(QLineEdit.Password)
        self.vt_key_edit.setPlaceholderText("Enter your VirusTotal API key...")
        layout.addRow("VirusTotal API Key:", self.vt_key_edit)

        # OTX
        self.otx_key_edit = QLineEdit()
        self.otx_key_edit.setEchoMode(QLineEdit.Password)
        self.otx_key_edit.setPlaceholderText("Enter your AlienVault OTX API key...")
        layout.addRow("AlienVault OTX API Key:", self.otx_key_edit)

        # AbuseIPDB
        self.abuse_key_edit = QLineEdit()
        self.abuse_key_edit.setEchoMode(QLineEdit.Password)
        self.abuse_key_edit.setPlaceholderText("Enter your AbuseIPDB API key...")
        layout.addRow("AbuseIPDB API Key:", self.abuse_key_edit)

        # API Help
        help_label = QLabel(
            "💡 <b>Getting API Keys:</b><br>"
            "• VirusTotal: https://www.virustotal.com/gui/user/apikey<br>"
            "• OTX: https://otx.alienvault.com/api<br>"
            "• AbuseIPDB: https://www.abuseipdb.com/api.html"
        )
        help_label.setOpenExternalLinks(True)
        help_label.setWordWrap(True)
        layout.addRow(help_label)

        return widget

    def create_appearance_tab(self):
        widget = QWidget()
        layout = QFormLayout(widget)

        # Theme Selection
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark", "Light", "System"])
        layout.addRow("Theme:", self.theme_combo)

        # Font Size
        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(8, 16)
        self.font_size_spin.setValue(11)
        self.font_size_spin.setSuffix(" pt")
        layout.addRow("Font Size:", self.font_size_spin)

        return widget

    def create_behavior_tab(self):
        widget = QWidget()
        layout = QFormLayout(widget)

        # Auto-export
        self.auto_export_check = QCheckBox("Automatically export results after analysis")
        layout.addRow(self.auto_export_check)

        # Cache duration
        self.cache_spin = QSpinBox()
        self.cache_spin.setRange(0, 86400)
        self.cache_spin.setValue(3600)
        self.cache_spin.setSuffix(" seconds")
        self.cache_spin.setSpecialValueText("Disabled")
        layout.addRow("Cache Duration:", self.cache_spin)

        # Concurrent requests
        self.concurrent_spin = QSpinBox()
        self.concurrent_spin.setRange(1, 10)
        self.concurrent_spin.setValue(5)
        layout.addRow("Max Concurrent Requests:", self.concurrent_spin)

        # Risk threshold
        self.risk_threshold_spin = QSpinBox()
        self.risk_threshold_spin.setRange(0, 100)
        self.risk_threshold_spin.setValue(70)
        self.risk_threshold_spin.setSuffix("%")
        layout.addRow("High Risk Threshold:", self.risk_threshold_spin)

        return widget

    def load_current_settings(self):
        """Load current settings into the form"""
        # API Keys (mask existing keys)
        self.vt_key_edit.setText("•" * 20 if self.config.get_api_key('virustotal') else "")
        self.otx_key_edit.setText("•" * 20 if self.config.get_api_key('otx') else "")
        self.abuse_key_edit.setText("•" * 20 if self.config.get_api_key('abuseipdb') else "")

        # Appearance
        theme = self.config.get_setting('SETTINGS', 'theme', 'dark')
        self.theme_combo.setCurrentText(theme.title())

        # Behavior
        self.auto_export_check.setChecked(
            self.config.get_setting('SETTINGS', 'auto_export', 'false').lower() == 'true'
        )
        self.cache_spin.setValue(int(self.config.get_setting('SETTINGS', 'cache_duration', '3600')))
        self.concurrent_spin.setValue(int(self.config.get_setting('SETTINGS', 'max_concurrent_requests', '5')))
        self.risk_threshold_spin.setValue(int(self.config.get_setting('SETTINGS', 'risk_threshold', '70')))

    def save_settings(self):
        """Save settings to configuration file"""
        try:
            # Save API Keys (only if changed)
            if not self.vt_key_edit.text().startswith('•'):
                self.config.set_api_key('virustotal', self.vt_key_edit.text())
            if not self.otx_key_edit.text().startswith('•'):
                self.config.set_api_key('otx', self.otx_key_edit.text())
            if not self.abuse_key_edit.text().startswith('•'):
                self.config.set_api_key('abuseipdb', self.abuse_key_edit.text())

            # Save Settings
            self.config.set_setting('SETTINGS', 'theme', self.theme_combo.currentText().lower())
            self.config.set_setting('SETTINGS', 'auto_export', str(self.auto_export_check.isChecked()).lower())
            self.config.set_setting('SETTINGS', 'cache_duration', str(self.cache_spin.value()))
            self.config.set_setting('SETTINGS', 'max_concurrent_requests', str(self.concurrent_spin.value()))
            self.config.set_setting('SETTINGS', 'risk_threshold', str(self.risk_threshold_spin.value()))

            QMessageBox.information(self, "Success", "Settings saved successfully!")
            self.accept()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save settings: {str(e)}")

    def test_connections(self):
        """Test API connections with current keys"""
        QMessageBox.information(self, "Test Feature",
                                "API connection testing will be implemented in the next version!")

    def get_style_sheet(self):
        return """
            QDialog {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QLabel {
                color: #ffffff;
            }
            QLineEdit, QComboBox, QSpinBox {
                background-color: #3c3c3c;
                color: #ffffff;
                border: 1px solid #555555;
                border-radius: 3px;
                padding: 5px;
            }
            QPushButton {
                background-color: #0078d4;
                color: white;
                border: none;
                border-radius: 3px;
                padding: 8px 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
            QTabWidget::pane {
                border: 1px solid #555555;
                background-color: #2b2b2b;
            }
            QTabBar::tab {
                background-color: #3c3c3c;
                color: #ffffff;
                padding: 8px 15px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #0078d4;
            }
        """