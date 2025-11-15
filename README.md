# HashVigil / IOC-Hunter 

A powerful desktop threat intelligence application for analyzing file hashes and IP addresses against multiple public threat intelligence APIs. Built for security analysts, SOC teams, and cybersecurity professionals.

![HashVigil v2.0](https://img.shields.io/badge/Version-2.0.0-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

##  What's New in v2.0!

- ** Theme System** - Dark/Light mode switching with persistent preferences
- ** Settings Management** - GUI configuration window for API keys and preferences
- ** Professional Menu** - File, View, Help menus with enhanced navigation
- ** Persistent Configuration** - Remembers your theme and settings between sessions
- ** Enhanced Architecture** - Centralized config management and modular design

##  Features

- **Multi-Source Analysis**: Check file hashes (MD5, SHA256) against VirusTotal and AlienVault OTX
- **IP Reputation**: Check IP addresses against AbuseIPDB for abuse reports and confidence scores
- **Risk Assessment**: Consolidated risk scoring with color-coded threat levels (🟢 LOW, 🟡 MEDIUM, 🔴 HIGH)
- **Bulk Analysis**: Import and analyze multiple IOCs from text files
- **Export Results**: Save analysis results to JSON or CSV formats
- **User-Friendly GUI**: Clean PyQt5 interface with real-time progress indicators
- **Theme Support**: Switch between Dark and Light themes
- **Standalone Executable**: No Python installation required - just download and run

##  Quick Start

### Option 1: Download Executable (Recommended for End Users)
1. Download the latest `HashVigil.exe` from [Releases](https://github.com/APMarzuki/HashVigil/releases)
2. Run `HashVigil.exe`
3. Configure API keys via `File → Settings` in the application

### Option 2: Run from Source (For Developers)
```bash
# Clone the repository
git clone https://github.com/APMarzuki/HashVigil.git
cd HashVigil

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py

# Configure API keys via File → Settings in the app
 Configuration
API Keys Setup (v2.0 Method - Recommended)
Open HashVigil

Go to File → Settings

Navigate to the "API Keys" tab

Enter your API keys for each service

Click "Save Settings"

Manual Configuration (Legacy Method)
Create config/settings.ini with your API keys:

ini
[API_KEYS]
; Get your free API keys from the following services:
; VirusTotal: https://www.virustotal.com/gui/join-us
; AlienVault OTX: https://otx.alienvault.com/api
; AbuseIPDB: https://www.abuseipdb.com/account/api

virustotal = YOUR_VIRUSTOTAL_API_KEY_HERE
otx = YOUR_OTX_API_KEY_HERE
abuseipdb = YOUR_ABUSEIPDB_API_KEY_HERE

[SETTINGS]
theme = dark
cache_duration = 3600
max_concurrent_requests = 5
auto_export = false
risk_threshold = 70
Required API Keys
VirusTotal: Free tier available (500 requests/day)

AlienVault OTX: Completely free, unlimited requests

AbuseIPDB: Free tier available (1,000 requests/day)

 Building from Source
Prerequisites
Python 3.8+

pip

Build Steps
bash
# Install dependencies
pip install -r requirements.txt

# Build executable
python build.py

# The executable will be in the 'dist' folder
 Usage Examples
Analyzing File Hashes
text
44d886d98f00b204e9800998ecf8427e  # Empty file (benign)
Analyzing IP Addresses
text
8.8.8.8           # Google DNS (clean)
185.220.101.141   # Known suspicious IP
Bulk Analysis
Create a text file with one IOC per line

Click "Bulk Import" and select your file

Review results for all IOCs

Theme Customization
Go to View → Theme

Select "Dark" or "Light" theme

Your preference is automatically saved

 Supported IOCs
Type	Format	Supported Services
File Hashes	MD5, SHA1, SHA256	VirusTotal, AlienVault OTX
IP Addresses	IPv4	AbuseIPDB
Project Structure
text
HashVigil/
├── core/                 # API integration modules
│   ├── api_virustotal.py
│   ├── api_otx.py
│   ├── api_abuseipdb.py
│   ├── aggregator.py
│   └── config_manager.py # v2.0: Centralized configuration
├── gui/                  # User interface
│   ├── main_window.py
│   └── settings_window.py # v2.0: Settings dialog
├── config/               # Configuration files
│   └── settings.ini
├── main.py              # Application entry point
├── build.py             # Build script
├── requirements.txt     # Python dependencies
└── README.md           # This file
 Troubleshooting
Common Issues
"API key not configured" errors

Use the Settings window (File → Settings) to configure API keys

Or ensure config/settings.ini exists with correct API keys

"No results" or timeouts

Check your internet connection

Verify API keys are valid and have remaining quota

Some APIs may have rate limits on free tiers

Application won't start

Ensure all dependencies are installed

Try running from source with python main.py for detailed error messages

Theme not saving

Ensure the application has write permissions in its directory

Check if config/settings.ini is not read-only

Contributing
We welcome contributions! Please feel free to submit pull requests, report bugs, or suggest new features.

Fork the repository

Create a feature branch (git checkout -b feature/amazing-feature)

Commit your changes (git commit -m 'Add some amazing feature')

Push to the branch (git push origin feature/amazing-feature)

Open a Pull Request

 License
This project is licensed under the MIT License - see the LICENSE file for details.
 Acknowledgments
VirusTotal for their comprehensive file analysis API

AlienVault OTX for open threat intelligence

AbuseIPDB for IP reputation data

PyQt5 for the GUI framework

Note: This tool is for legitimate security research and analysis purposes only. Always ensure you have proper authorization before analyzing systems or files that you do not own.

text

##  **Next Steps:**

1. **Copy this updated README.md** to your project
2. **Update the GitHub URL** if needed (replace `APMarzuki` with your actual username)
3. **Create the release** following the steps I mentioned earlier
4. **Take screenshots** of your v2.0 app (showing both dark and light themes, settings window)

##  **Suggested Screenshots:**
- Dark theme main window with analysis results
- Light theme main window  
- Settings window showing API keys tab
- About dialog

##  **Ready for GitHub Release!**

Your README is now updated with all v2.0 features. You're ready to:

```bash
git add README.md
git commit -m " Update README for v2.0 release"
git push origin main