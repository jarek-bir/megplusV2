# meg+ v2.0 - Enhanced Reconnaissance Framework

Advanced reconnaissance automation wrapper for [TomNomNom's meg](https://github.com/tomnomnom/meg) with comprehensive subdomain enumeration and security analysis.

## 🚀 Features

### Core Functionality
- **Multiple subdomain enumeration tools**: Sublist3r, Subfinder, or both combined
- **Intelligent request distribution**: meg's smart load balancing prevents detection
- **Comprehensive security analysis**: 500k+ patterns for vulnerabilities and secrets
- **Custom path scanning**: 188 curated reconnaissance endpoints
- **Automated results analysis**: Critical/High/Medium/Info severity classification

### Subdomain Discovery Options
- `-s domain.com` - **Sublist3r** enumeration
- `-sf domain.com` - **Subfinder** enumeration  
- `-all domain.com` - **Both tools combined** for maximum coverage
- **Automatic httprobe validation** for active endpoints only

## 📦 Installation

### Prerequisites
```bash
# Required
go install github.com/tomnomnom/meg@latest

# Optional (for enhanced subdomain discovery)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/httprobe@latest
```

### Quick Setup
```bash
git clone https://github.com/jarek-bir/megplusV2.git
cd megplusV2
chmod +x *.sh
```

## 🎯 Usage Examples

### Subdomain Discovery & Scanning
```bash
# Sublist3r enumeration + full scan
./megplus.sh -s target.com

# Subfinder enumeration + full scan  
./megplus.sh -sf target.com

# BEAST MODE: Both tools + full scan
./megplus.sh -all target.com
```

### Results Analysis
```bash
# Interactive results browser
./browse_results.sh -s    # Summary
./browse_results.sh -2    # All 200 responses

# Comprehensive security analysis
./findall.sh out/
```

## 🔍 What Gets Detected

- 🚨 **Critical**: Credentials, API keys, private keys
- 🔥 **High**: XSS, SQLi, subdomain takeovers  
- ⚠️ **Medium**: Config files, debug modes
- ℹ️ **Info**: Technology fingerprinting

---

**meg+ v2.0** - Enhanced reconnaissance framework 🎯
