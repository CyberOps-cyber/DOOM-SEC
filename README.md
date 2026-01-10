# DOOM-SEC

A comprehensive collection of security tools for penetration testing, reconnaissance, and vulnerability assessment. This toolkit provides various utilities for ethical hackers and security researchers.

## ⚠️ Disclaimer

**This toolkit is for educational and authorized security testing purposes only. Use only on systems you own or have explicit permission to test. Unauthorized use may violate laws and regulations.**

## 🛠️ Tools Included

### Python Tools

#### 🔍 **recon.py** - Domain Reconnaissance
- IP resolution
- DNS record enumeration
- Subdomain discovery
- Website fingerprinting

```bash
python recon.py <domain>
```

#### 🛡️ **api_logic_sentinel.py** - API Security Testing
- IDOR (Insecure Direct Object References) testing
- Method tampering detection
- Role confusion testing
- Rate limiting assessment

```bash
python api_logic_sentinel.py <base_url> <token> <endpoint>
```

#### 🔐 **jwt_analyzer.py** - JWT Token Analysis
- Token decoding and validation
- Algorithm detection
- Signature verification

#### 🌐 **JavaScript_Endpoint_&_Secret_Finder.py** - JavaScript Analysis
- Endpoint discovery in JS files
- Secret/API key detection
- Source code analysis

#### 📡 **arp_spoofer.py** - ARP Spoofing
- Man-in-the-middle attack simulation
- Network traffic interception

#### 🔍 **authflow_inspector.py** - Authentication Flow Analysis
- Login/logout flow testing
- Session management assessment

#### 💀 **RevShell.py** - Reverse Shell
- Remote shell establishment
- Command execution over network

#### 🛡️ **shadowbrute.py** - Subdomain Brute-Forcing
- Multi-threaded subdomain enumeration
- DNS resolution
- Progress tracking

```bash
python shadowbrute.py <domain> <wordlist>
```

#### 😴 **SleepBackdoor.py** - Sleep-Based Backdoor
- Time-based command execution
- Evasion techniques

#### 🌀 **vortexscan.py** - Network Scanning
- Port scanning
- Service detection
- Vulnerability assessment

### Go Tools

#### 👻 **ghostbeacon.go** - C2 Beacon Simulator
- Command and control simulation
- Encrypted communications
- Randomized beaconing

```bash
go run ghostbeacon.go
```

#### 🔄 **redirect_hunter.go** - Redirect Analysis
- Open redirect vulnerability testing
- URL redirection chains

#### 🚀 **redirector.go** - Redirect Server
- HTTP redirect server
- Custom redirect rules

#### 🌊 **trafficforge.go** - Traffic Generation
- Network traffic simulation
- Load testing
- Packet crafting

### C Tools

#### 💥 **idorcrusher.c** - IDOR Testing
- Direct object reference exploitation
- Automated IDOR scanning

```bash
gcc idorcrusher.c -o idorcrusher
./idorcrusher <target>
```

## 📋 Requirements

### Python Dependencies
```bash
pip install requests beautifulsoup4 dnspython
```

### Go Requirements
- Go 1.19+ installed
- Standard library (no external dependencies)

### C Requirements
- GCC compiler
- Standard C libraries

## 🚀 Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd DOOM-SEC
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. For Go tools, ensure Go is installed and run directly with `go run`

4. For C tools, compile with GCC:
```bash
gcc <tool>.c -o <tool>
```

## 📖 Usage

Each tool includes its own help system. Run tools without arguments to see usage instructions:

```bash
python <tool>.py --help
# or
go run <tool>.go --help
# or
./<compiled_tool> --help
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔗 Links

- [Project telegram](https://github.com/your-org/DOOM-SEC/wiki)

---

**Remember: With great power comes great responsibility. Use these tools ethically and legally.**