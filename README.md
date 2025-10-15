# 🛡️ SQL Injection Vulnerability Scanner

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A powerful and educational Python-based security tool designed to detect SQL injection vulnerabilities in web applications by analyzing HTML forms and testing them with various SQL injection payloads.

![SQL Injection Scanner Demo](https://img.shields.io/badge/status-active-success.svg)

## ✨ Features

- **Automated Form Detection**: Automatically discovers and analyzes all HTML forms on a target webpage
- **Multiple Injection Payloads**: Tests forms with a comprehensive set of SQL injection patterns
- **Support for All Form Elements**: Analyzes input fields, textareas, select dropdowns, and hidden fields
- **Both GET and POST Methods**: Handles forms with different HTTP methods
- **Relative URL Resolution**: Properly resolves form actions regardless of URL format
- **Rate Limiting**: Includes delays to prevent server overload

## 🔍 How It Works

1. **Form Discovery**: The scanner fetches the target URL and parses the HTML to identify all forms
2. **Form Analysis**: Extracts form details including action URL, HTTP method, and all input fields
3. **Payload Injection**: Systematically injects SQL injection payloads into form fields
4. **Response Analysis**: Examines server responses for SQL error messages indicating vulnerabilities
5. **Vulnerability Reporting**: Reports any detected vulnerabilities with specific details

### Tested Payloads

```sql
'
"
' OR '1'='1
" OR "1"="1
' OR 1=1--
" OR 1=1--
'; DROP TABLE users--
1' OR '1'='1
```

### Detected Error Patterns

The scanner identifies SQL errors from:
- MySQL
- PostgreSQL
- SQLite
- Oracle
- SQL Server
- Generic SQL syntax errors

## 🚀 Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/sql-injection-scanner.git
cd sql-injection-scanner
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

### Requirements

Create a `requirements.txt` file with:
```
requests>=2.28.0
beautifulsoup4>=4.11.0
lxml>=4.9.0
```

## 💻 Usage

### Interactive Mode

```bash
python sql_scanner.py
```

You'll be prompted to enter the URL to scan.

### Command Line Mode

```bash
python sql_scanner.py https://example.com
```

### Example Output

```
============================================================
SQL INJECTION VULNERABILITY SCANNER
============================================================

⚠️  WARNING: Only test websites you own or have permission to test!
    Unauthorized testing may be illegal.

============================================================

[*] Starting SQL injection scan on: https://testsite.com

[+] Detected 2 forms on https://testsite.com.

[*] Testing form #1
    Action: https://testsite.com/login
    Method: POST
    Inputs: 3

[!] SQL INJECTION VULNERABILITY DETECTED!
    URL: https://testsite.com/login
    Method: POST
    Payload: ' OR '1'='1

[*] Scan complete.
```

## 🔧 Technical Details

### Architecture

```
sql_scanner.py
│
├── get_forms(url)              # Fetches and parses HTML forms
├── form_details(form, base_url) # Extracts form metadata
├── vulnerable(response)         # Analyzes response for SQL errors
└── sql_injection_scan(url)     # Main scanning orchestrator
```

### Key Technologies

- **Requests**: HTTP library for making web requests
- **BeautifulSoup4**: HTML parsing and form extraction
- **urllib.parse**: URL manipulation and resolution

### Database Support

The scanner detects vulnerabilities in web applications using:
- MySQL
- PostgreSQL
- SQLite
- Oracle Database
- Microsoft SQL Server
- Other SQL-based databases
