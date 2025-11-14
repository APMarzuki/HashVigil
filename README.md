# HashVigil / IOC-Hunter 🔍

A powerful desktop threat intelligence application for analyzing file hashes and IP addresses against multiple public threat intelligence APIs. Built for security analysts, SOC teams, and cybersecurity professionals.

![HashVigil Screenshot](https://via.placeholder.com/800x400.png?text=HashVigil+Screenshot) *// You can add actual screenshots later*

## ✨ Features

- **Multi-Source Analysis**: Check file hashes (MD5, SHA256) against VirusTotal and AlienVault OTX
- **IP Reputation**: Check IP addresses against AbuseIPDB for abuse reports and confidence scores
- **Risk Assessment**: Consolidated risk scoring with color-coded threat levels (🟢 LOW, 🟡 MEDIUM, 🔴 HIGH)
- **Bulk Analysis**: Import and analyze multiple IOCs from text files
- **Export Results**: Save analysis results to JSON or CSV formats
- **User-Friendly GUI**: Clean PyQt5 interface with real-time progress indicators
- **Standalone Executable**: No Python installation required - just download and run

## 🚀 Quick Start

### Option 1: Download Executable (Recommended for End Users)
1. Download the latest `HashVigil.exe` from [Releases](../../releases)
2. Create a `config` folder in the same directory as the executable
3. Create `config/settings.ini` with your API keys (see Configuration section)
4. Run `HashVigil.exe`

### Option 2: Run from Source (For Developers)
```bash
# Clone the repository
git clone https://github.com/APMarzuki/HashVigil.git
cd HashVigil

# Install dependencies
pip install -r requirements.txt

# Configure API keys
cp config/settings_template.ini config/settings.ini
# Edit config/settings.ini with your API keys

# Run the application
python main.py
⚙️ Configuration
API Keys Setup
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
cache_duration = 3600
max_concurrent_requests = 5
Required API Keys
VirusTotal: Free tier available (500 requests/day)

AlienVault OTX: Completely free, unlimited requests

AbuseIPDB: Free tier available (1,000 requests/day)

🛠️ Building from Source
Prerequisites
Python 3.8+

pip

Build Steps
bash
# Install dependencies
pip install -r requirements.txt

# Build executable
python build.py
# or manually:
pyinstaller --onefile --windowed --name HashVigil --add-data "config;config" main.py

# The executable will be in the 'dist' folder
📊 Usage Examples
Analyzing File Hashes
text
44d88612fea8a8f36de82e1278abb02f  # EICAR test file (malicious)
d41d8cd98f00b204e9800998ecf8427e  # Empty file (benign)
Analyzing IP Addresses
text
8.8.8.8           # Google DNS (clean)
185.220.101.141   # Known suspicious IP
Bulk Analysis
Create a text file with one IOC per line

Click "Bulk Import" and select your file

Review results for all IOCs

🎯 Supported IOCs
Type	Format	Supported Services
File Hashes	MD5, SHA1, SHA256	VirusTotal, AlienVault OTX
IP Addresses	IPv4	AbuseIPDB
📁 Project Structure
text
HashVigil/
├── core/                 # API integration modules
│   ├── api_virustotal.py
│   ├── api_otx.py
│   ├── api_abuseipdb.py
│   └── aggregator.py
├── gui/                  # User interface
│   └── main_window.py
├── config/               # Configuration files
│   └── settings.ini
├── main.py              # Application entry point
├── build.py             # Build script
├── requirements.txt     # Python dependencies
└── README.md           # This file
🐛 Troubleshooting
Common Issues
"API key not configured" errors

Ensure config/settings.ini exists with correct API keys

Verify the config file is in the same directory as the executable

"No results" or timeouts

Check your internet connection

Verify API keys are valid and have remaining quota

Some APIs may have rate limits on free tiers

Application won't start

Ensure all dependencies are installed

Try running from source with python main.py for detailed error messages

🤝 Contributing
We welcome contributions! Please feel free to submit pull requests, report bugs, or suggest new features.

Fork the repository

Create a feature branch (git checkout -b feature/amazing-feature)

Commit your changes (git commit -m 'Add some amazing feature')

Push to the branch (git push origin feature/amazing-feature)

Open a Pull Request

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

🙏 Acknowledgments
VirusTotal for their comprehensive file analysis API

AlienVault OTX for open threat intelligence

AbuseIPDB for IP reputation data

PyQt5 for the GUI framework

Note: This tool is for legitimate security research and analysis purposes only. Always ensure you have proper authorization before analyzing systems or files that you do not own.

text

## What Was Fixed:

1. **Missing section headers** - Added proper `##` headers for Configuration, Building, etc.
2. **Code block formatting** - Fixed the code blocks that were broken
3. **Table formatting** - Fixed the Supported IOCs table
4. **List formatting** - Fixed bullet points and numbered lists
5. **Proper markdown syntax** throughout

## Final Steps Before GitHub Upload:

1. **Replace the GitHub URL**: Change `APMarzuki` to your actual GitHub username
2. **Create settings_template.ini**: Create this file in your `config` folder
3. **Take actual screenshots**: Replace the placeholder image with real screenshots of your app
4. **Test the build process**: Make sure `python build.py` works correctly

## Create `config/settings_template.ini`:

```ini
[API_KEYS]
; Get your free API keys from the following services:
; VirusTotal: https://www.virustotal.com/gui/join-us
; AlienVault OTX: https://otx.alienvault.com/api
; AbuseIPDB: https://www.abuseipdb.com/account/api

virustotal = YOUR_VIRUSTOTAL_API_KEY_HERE
otx = YOUR_OTX_API_KEY_HERE
abuseipdb = YOUR_ABUSEIPDB_API_KEY_HERE

[SETTINGS]
cache_duration = 3600
max_concurrent_requests = 5