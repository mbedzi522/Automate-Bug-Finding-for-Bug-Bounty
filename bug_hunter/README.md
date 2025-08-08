# Bug Hunter Tool 🔍

An advanced automated bug hunting tool designed for bug bounty programs, featuring AI-powered vulnerability analysis using Google's Gemini API.

## 🚀 Features

### Core Capabilities
- **Automated Reconnaissance**: Comprehensive subdomain enumeration, port scanning, and service detection
- **Vulnerability Scanning**: Integration with industry-standard tools (Nmap, Nuclei, SQLMap, Gobuster)
- **AI-Powered Analysis**: Intelligent vulnerability prioritization and false positive detection using Gemini API
- **Comprehensive Reporting**: HTML, JSON, CSV, and executive summary reports
- **Multi-threaded Execution**: Efficient parallel processing for faster scans
- **Modular Architecture**: Extensible design for easy customization and enhancement

### Supported Vulnerability Types
- SQL Injection
- Cross-Site Scripting (XSS)
- Directory Traversal
- Information Disclosure
- Security Misconfigurations
- SSL/TLS Vulnerabilities
- CMS-specific Vulnerabilities (WordPress, Drupal, Joomla)
- Network-level Vulnerabilities

### AI Analysis Features
- Vulnerability prioritization based on exploitability and impact
- False positive detection and filtering
- Custom payload generation
- Attack vector analysis
- Risk assessment and threat intelligence
- Remediation suggestions

## 📋 Requirements

### System Requirements
- Linux (Ubuntu 22.04+ recommended)
- Python 3.8+
- Root privileges (for some network scanning features)
- Internet connection

### Required Tools
The following tools are automatically installed or configured:
- Nmap
- Nuclei
- SQLMap
- Gobuster
- Sublist3r
- Nikto

### Python Dependencies
See `requirements.txt` for a complete list. Key dependencies include:
- requests
- google-generativeai
- dnspython
- pyyaml
- beautifulsoup4

## 🛠️ Installation

### Quick Installation
```bash
# Clone the repository
git clone https://github.com/your-repo/bug-hunter-tool.git
cd bug-hunter-tool

# Install Python dependencies
pip3 install -r requirements.txt

# Install system tools (Ubuntu/Debian)
sudo apt update
sudo apt install -y nmap nikto dirb sqlmap gobuster

# Install Nuclei
wget -O nuclei.zip https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip
unzip nuclei.zip
sudo mv nuclei /usr/local/bin/
rm nuclei.zip

# Install Sublist3r
pip3 install sublist3r

# Make the main script executable
chmod +x main.py
```

### Using Setup Script
```bash
python3 setup.py install
```

## ⚙️ Configuration

### Basic Configuration
Copy the default configuration file and customize as needed:
```bash
cp config/default_config.yaml config/my_config.yaml
```

### AI Integration Setup
To enable AI-powered analysis, set your Gemini API key:
```bash
export GEMINI_API_KEY="your_gemini_api_key_here"
```

Or add it to your configuration file:
```yaml
ai_analysis:
  enabled: true
  gemini_api_key: "your_api_key_here"
```

### Configuration Options
Key configuration sections:
- `general`: Threading, timeouts, user agent
- `reconnaissance`: Subdomain enumeration, port scanning options
- `vulnerability_scanning`: Scan types and tool configurations
- `ai_analysis`: Gemini API settings and analysis types
- `reporting`: Output formats and options
- `tools`: Tool paths and default arguments

## 🚀 Usage

### Basic Usage
```bash
# Full scan of a single target
python3 main.py -t example.com --full-scan

# Reconnaissance only
python3 main.py -t example.com --recon-only

# Vulnerability scanning only
python3 main.py -t example.com --vuln-scan

# AI analysis enabled
python3 main.py -t example.com --ai-analysis
```

### Advanced Usage
```bash
# Batch scanning from file
python3 main.py -f targets.txt --batch-mode

# Custom configuration
python3 main.py -t example.com --config my_config.yaml

# Custom output directory
python3 main.py -t example.com --output-dir /path/to/reports

# Adjust threading and timeout
python3 main.py -t example.com --threads 20 --timeout 60

# Verbose logging
python3 main.py -t example.com --verbose --log-level DEBUG
```

### Target File Format
Create a text file with one target per line:
```
example.com
test.example.com
192.168.1.1
subdomain.target.org
```

## 📊 Reports

### Report Types
1. **HTML Report**: Interactive web-based report with filtering and collapsible sections
2. **JSON Report**: Raw data in JSON format for programmatic processing
3. **CSV Report**: Vulnerability list in CSV format for spreadsheet analysis
4. **Executive Summary**: High-level markdown summary for management

### Report Features
- Vulnerability severity classification
- Interactive filtering by severity level
- Detailed evidence and remediation suggestions
- Attack surface analysis
- AI-powered insights and recommendations

## 🤖 AI Integration

### Gemini API Features
The tool integrates with Google's Gemini API to provide:

1. **Vulnerability Prioritization**: AI analyzes vulnerabilities based on exploitability, business impact, and attack complexity
2. **False Positive Detection**: Reduces noise by identifying likely false positives
3. **Attack Vector Analysis**: Identifies potential attack chains and escalation paths
4. **Custom Payload Generation**: Creates context-aware payloads for specific technologies
5. **Risk Assessment**: Provides comprehensive risk analysis and threat intelligence
6. **Remediation Suggestions**: Generates detailed, actionable remediation guidance

### API Key Setup
1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create a new API key
3. Set the environment variable: `export GEMINI_API_KEY="your_key"`

## 🔧 Customization

### Adding Custom Modules
The tool's modular architecture allows easy extension:

1. Create new modules in the `modules/` directory
2. Follow the existing interface patterns
3. Update the configuration to include new module settings
4. Import and integrate in `core.py`

### Custom Payloads
Add custom payloads by:
1. Extending the `PayloadUtils` class in `utils.py`
2. Creating payload files in a `payloads/` directory
3. Configuring payload paths in the configuration file

### Custom Wordlists
Configure custom wordlists in the configuration:
```yaml
wordlists:
  subdomains:
    - "/path/to/custom/subdomains.txt"
  directories:
    - "/path/to/custom/directories.txt"
```

## 🛡️ Security Considerations

### Ethical Usage
- Only test targets you own or have explicit permission to test
- Respect rate limits and avoid overwhelming target systems
- Follow responsible disclosure practices for any vulnerabilities found
- Comply with all applicable laws and regulations

### Tool Safety
- The tool includes safety measures to prevent destructive actions
- All payloads are designed to be non-destructive
- Rate limiting and delays are implemented to avoid DoS conditions
- Comprehensive logging for audit trails

## 🐛 Troubleshooting

### Common Issues

#### Permission Errors
Some features require root privileges:
```bash
sudo python3 main.py -t example.com --full-scan
```

#### Tool Not Found Errors
Ensure all required tools are installed and in PATH:
```bash
which nmap nuclei sqlmap gobuster
```

#### API Rate Limiting
If you encounter Gemini API rate limits:
1. Reduce the number of concurrent requests
2. Add delays between API calls
3. Check your API quota and billing

#### Network Connectivity
For targets behind firewalls or with strict filtering:
1. Adjust timeout values
2. Use different scan techniques
3. Consider using proxy or VPN

### Debug Mode
Enable debug logging for troubleshooting:
```bash
python3 main.py -t example.com --log-level DEBUG --verbose
```

## 📈 Performance Optimization

### Threading Configuration
Optimize performance based on your system:
```bash
# High-performance system
python3 main.py -t example.com --threads 50

# Limited resources
python3 main.py -t example.com --threads 5
```

### Memory Management
For large-scale scans:
1. Process targets in batches
2. Use the `--batch-mode` flag
3. Monitor system resources
4. Consider using multiple instances

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a virtual environment
3. Install development dependencies
4. Run tests before submitting PRs

### Code Style
- Follow PEP 8 guidelines
- Use type hints where appropriate
- Include comprehensive docstrings
- Add unit tests for new features

### Reporting Issues
When reporting issues, include:
1. Tool version and configuration
2. Target information (if safe to share)
3. Complete error messages and logs
4. Steps to reproduce the issue

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is intended for authorized security testing only. Users are responsible for ensuring they have proper authorization before testing any targets. The developers are not responsible for any misuse of this tool.

## 🙏 Acknowledgments

- Google for the Gemini API
- The open-source security community
- Contributors to the integrated tools (Nmap, Nuclei, SQLMap, etc.)
- Bug bounty platforms for inspiration and testing opportunities

## 📞 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation and troubleshooting guide
- Review existing issues for similar problems

---

**Happy Bug Hunting! 🐛🔍**

