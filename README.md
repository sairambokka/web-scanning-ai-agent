# Web Security Scanner AI Agent

A powerful multi-agent system that performs comprehensive security analysis of web applications using AI agents and automated browser testing.

## 🔍 Overview

This project leverages multiple AI agents to conduct thorough security assessments of web applications, combining automated browser testing with intelligent analysis to identify vulnerabilities across frontend and network layers.

## ✨ Features

- **Multi-Agent Architecture**: Specialized AI agents for different security domains
- **Automated Browser Testing**: Real-time network monitoring and DOM analysis
- **Industry-Specific Analysis**: Tailored security assessments based on industry standards
- **Comprehensive Reporting**: Detailed vulnerability reports with actionable remediation steps
- **Frontend Security Analysis**: XSS, CSRF, input validation, and CSP assessment
- **Network Security Analysis**: Authentication, encryption, session management, and API security
- **Real-time Network Monitoring**: Captures and analyzes HTTP requests/responses

## 🏗️ Architecture

### AI Agents

1. **Industry Analyst Agent**: Analyzes industry-specific security standards and protocols
2. **Frontend Security Agent**: Focuses on client-side vulnerabilities and browser security
3. **Network Security Agent**: Evaluates server-side security, encryption, and network protocols
4. **Summary & Briefing Agent**: Consolidates findings into comprehensive reports

### Tools & Technologies

- **CrewAI**: Multi-agent orchestration framework
- **Selenium**: Automated browser testing and network monitoring
- **Exa AI**: Advanced web search and content analysis
- **NVIDIA AI**: Advanced language models via NVIDIA's API for intelligent security analysis
- **BeautifulSoup**: HTML parsing and analysis

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Chrome/Brave Browser installed
- ChromeDriver compatible with your browser version

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/web-scanning-ai-agent.git
cd web-scanning-ai-agent
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
cp .env.example .env
```

4. Configure your `.env` file:
```env
EXA_API_KEY=your_exa_api_key_here
OPENAI_API_KEY=your_nvidia_api_key_here  # NVIDIA API key from build.nvidia.com
CHROMEDRIVER_PATH=/path/to/your/chromedriver
CHROME_BINARY_PATH=/path/to/your/chrome/binary
```

### Usage

Run the security scanner:
```bash
python main.py
```

Enter the target URL when prompted, and the system will:
1. Perform automated browser testing
2. Capture network logs and DOM data
3. Deploy AI agents for comprehensive analysis
4. Generate detailed security reports

## 📊 Analysis Categories

### Frontend Security
- Input validation and sanitization
- Cross-Site Scripting (XSS) protection
- Cross-Site Request Forgery (CSRF) prevention
- Content Security Policy (CSP) implementation
- Security headers configuration
- JavaScript security assessment
- File upload security
- Form validation

### Network Security
- Authentication and authorization mechanisms
- Data encryption (in transit and at rest)
- Session management
- Security headers analysis
- Access control evaluation
- API security assessment
- TLS/SSL configuration
- Vulnerability management

### Special Checks
- `/robots.txt` exposure analysis
- `/.well-known/security.txt` compliance
- Third-party script security
- Mixed content detection
- Certificate validation
- Cookie security flags

## 📋 Sample Output

```
Vulnerability Report: Example Website

Introduction
This report presents security vulnerabilities identified through automated testing and AI analysis.

Vulnerabilities Found
1. Missing Content Security Policy (CSP) headers
2. Insecure session cookie configuration
3. Absence of X-Frame-Options header
4. Potential XSS vulnerabilities in user input fields
5. Missing HSTS header implementation

Steps to solve the vulnerabilities
1. Implement strict CSP headers with nonce-based script execution
2. Configure cookies with HttpOnly and Secure flags
3. Add X-Frame-Options: DENY header
4. Implement input validation and output encoding
5. Enable HSTS with appropriate max-age directive

In conclusion
The website requires immediate attention to critical security headers and input validation mechanisms.

Note
Regular security assessments and automated testing should be implemented as part of the development lifecycle.
```

## 🔧 Configuration

### Browser Setup

The system supports both Chrome and Brave browsers. Update the `chrome_binary_path` in `utils.py`:

```python
chrome_binary_path = "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"
```

### Agent Configuration

Customize agent behavior by modifying the `SecurityAnalysisAgents` class in `helpers.py`. The agents use NVIDIA's language models via ChatNVIDIA:

```python
def frontend_security_agent(self):
    return Agent(
        role='Frontend security Analyst',
        goal='Check for security breaches on the front end',
        tools=ExaSearchTool.tools(),
        llm=self.llama3,  # Uses NVIDIA API via ChatNVIDIA
        backstory=dedent("""\
            Custom backstory for specialized analysis...
        """),
        verbose=True
    )
```

**Note**: The NVIDIA API key should be set as `OPENAI_API_KEY` in your environment variables for compatibility with the ChatNVIDIA integration.

## 📁 Project Structure

```
web-scanning-ai-agent/
├── main.py                 # Main execution script
├── helpers.py              # AI agents and task definitions
├── utils.py               # Utility functions for browser automation
├── requirements.txt       # Python dependencies
├── .env                   # Environment variables (create from .env.example)
├── .gitignore            # Git ignore rules
└── README.md             # Project documentation
```

## 🔑 API Keys Required

1. **NVIDIA API Key**: For LLM inference and AI agent operations using NVIDIA's language models
   - Sign up at [NVIDIA Build Platform](https://build.nvidia.com/)
   - Generate API key and add to `.env` as `OPENAI_API_KEY` (required for compatibility)

2. **Exa API Key**: For web search capabilities
   - Register at [Exa AI](https://exa.ai/)
   - Obtain API key and configure in `.env`

## 🛡️ Security Considerations

- This tool is intended for authorized security testing only
- Always obtain proper permission before scanning websites
- Use responsibly and in compliance with applicable laws
- The tool may generate network traffic that could be detected
- Consider rate limiting for production environments

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Commit changes: `git commit -am 'Add new feature'`
4. Push to branch: `git push origin feature/new-feature`
5. Submit a pull request


## 🆘 Support

For issues and questions:
- Create an issue in the GitHub repository
- Check existing documentation and examples
- Review the troubleshooting section below

## 🔧 Troubleshooting

### Common Issues

**ChromeDriver not found**
```bash
# Download ChromeDriver and update CHROMEDRIVER_PATH in .env
wget https://chromedriver.chromium.org/downloads
```

**API Key errors**
```bash
# Verify API keys are properly set
python -c "import os; print(os.getenv('OPENAI_API_KEY'))"  # This should show your NVIDIA API key
python -c "import os; print(os.getenv('EXA_API_KEY'))"
```

**Browser automation failures**
- Ensure browser is installed and accessible
- Check ChromeDriver compatibility
- Verify headless mode configuration

## 🚧 Future Enhancements

- [ ] Database vulnerability scanning
- [ ] API endpoint fuzzing
- [ ] Automated penetration testing
- [ ] Integration with CI/CD pipelines
- [ ] Real-time monitoring capabilities
- [ ] Mobile application security testing

---

**⚠️ Disclaimer**: This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.