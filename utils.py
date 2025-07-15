# utils.py
import os
import json
import re
import datetime
from collections import defaultdict
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.chrome.service import Service # Import Service

# For local development, use python-dotenv to load from .env file
from dotenv import load_dotenv
load_dotenv()

def get_api_keys():
    """Retrieves API keys from environment variables."""
    openai_api_key = os.getenv("OPENAI_API_KEY")
    exa_api_key = os.getenv("EXA_API_KEY")
    if not openai_api_key or not exa_api_key:
        raise ValueError("GROQ_API_KEY and EXA_API_KEY must be set in environment variables or .env file.")
    return openai_api_key, exa_api_key

def get_network_and_dom_data(url):
    """
    Automates a browser to get network logs and DOM source code.
    This function relies on Google Colab's specific Selenium setup.
    For local execution, you might need to adjust the Selenium setup
    to use a local ChromeDriver.
    """
    chromedriver_path = os.getenv("CHROMEDRIVER_PATH")
    service_obj = Service(chromedriver_path) # Create a Service object

    options = Options()
    options.add_argument("--headless") # Run Chrome in headless mode (no GUI)
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--disable-gpu") # Recommended for headless mode
    options.add_argument("--no-sandbox") # Required for some environments (e.g., Docker)
    options.add_argument("--disable-dev-shm-usage") # Required for some environments
    chrome_binary_path = os.getenv("CHROME_BINARY_PATH")
    options.binary_location = chrome_binary_path
    # Set up desired capabilities for logging
    options.set_capability('goog:loggingPrefs', {'browser': 'ALL', 'performance': 'ALL'})

    driver = webdriver.Chrome(service=service_obj, options=options)

    try:
        driver.get(url)
        src = driver.page_source
        network_logs = driver.get_log('performance')
        return src, network_logs
    except Exception as e:
        print(f"Error during browser automation: {e}")
        return "", []
    finally:
        driver.quit()

def extract_meaning_from_log_strings(log_string, extracted_data):
    """Extracts relevant data from a single network log entry."""
    try:
        log_entry = json.loads(log_string)
        message = log_entry['message']
        params = message['params']

        # HTTP requests and responses
        if 'requestWillBeSent' in message['method']:
            request_data = {
                'url': params['request']['url'],
                'method': params['request']['method'],
                'headers': params['request']['headers'],
                'initiator': params.get('initiator', {}).get('url'),
            }
            extracted_data['http_requests'].append(request_data)
        elif 'responseReceived' in message['method']:
            response_data = {
                'url': params['response']['url'],
                'status_code': params['response']['status'],
                'headers': params['response']['headers'],
            }
            extracted_data['http_requests'].append(response_data)

        # Resources
        if 'type' in params and 'response' in params:
            resource_type = params['type']
            extracted_data['resources'].append({
                'url': params['response']['url'],
                'type': resource_type,
            })

        # Webview actions
        if 'domContentEventFired' in message['method']:
            extracted_data['webview_actions'].append({'action': 'DOMContentLoaded'})
        elif 'loadEventFired' in message['method']:
            extracted_data['webview_actions'].append({'action': 'loadEventFired'})

    except json.JSONDecodeError:
        pass # Ignore malformed log entries
    except KeyError as e:
        pass # Ignore log entries missing expected keys

def analyze_network_data(network_logs_list):
    """Analyzes a list of network log entries to extract insights."""
    extracted_data = {
        'http_requests': [],
        'resources': [],
        'webview_actions': [],
    }

    for log_entry in network_logs_list:
        extract_meaning_from_log_strings(log_entry['message'], extracted_data)

    resource_counts = defaultdict(int)
    url_domains = defaultdict(set)
    http_request_observations = []
    third_party_domains = set()

    for data_point in extracted_data['http_requests']:
        url = data_point['url']
        resource_type = data_point.get('type', 'Unknown')
        resource_counts[resource_type] += 1

        match = re.search(r'https?://([^/]+)', url)
        if match:
            domain = match.group(1)
            url_domains[domain].add(url)

            if 'initiator' in data_point and data_point['initiator']:
                initiator_match = re.search(r'https?://([^/]+)', data_point['initiator'])
                if initiator_match and domain != initiator_match.group(1):
                    third_party_domains.add(domain)

        if 'headers' in data_point:
            headers = {k.lower(): v for k, v in data_point['headers'].items()} # Normalize headers to lowercase
            if 'content-security-policy' in headers:
                csp_value = headers['content-security-policy']
                if 'unsafe-inline' in csp_value or 'unsafe-eval' in csp_value:
                    http_request_observations.append(f"Potentially insecure Content-Security-Policy: {csp_value} in request for {url}")
            if 'x-frame-options' in headers:
                xfo_value = headers['x-frame-options']
                if xfo_value.lower() != 'deny':
                    http_request_observations.append(f"Potentially insecure X-Frame-Options: {xfo_value} in request for {url}")

    # Also process resources directly from extracted_data['resources']
    if 'resources' in extracted_data:
        for resource in extracted_data['resources']:
            url = resource['url']
            resource_type = resource['type']
            resource_counts[resource_type] += 1
            match = re.search(r'https?://([^/]+)', url)
            if match:
                domain = match.group(1)
                url_domains[domain].add(url)

    num_domains = len(url_domains)
    most_frequent_domain = max(url_domains, key=lambda k: len(url_domains[k])) if url_domains else None

    return {
        'resource_counts': dict(resource_counts),
        'url_domains': dict(url_domains),
        'http_request_observations': http_request_observations,
        'num_domains': num_domains,
        'most_frequent_domain': most_frequent_domain,
        'third_party_domains': list(third_party_domains)
    }

def analyze_security_flaws(logs):
    """Analyzes network logs for common security flaws."""
    flaws = []
    referrer_policy_set = False

    for log_entry in logs:
        try:
            message = json.loads(log_entry['message'])['message']
            params = message['params']

            if message['method'] == 'Network.requestWillBeSent':
                if params['request']['url'].startswith('http://') and params.get('documentURL', '').startswith('https://'):
                    flaws.append(f"Potential Mixed Content: {params['request']['url']}")
                if 'Referrer-Policy' in params['request']['headers']:
                    referrer_policy_set = True
                else:
                    if not referrer_policy_set: # Only add if it's the *initial* request or consistently missing
                        flaws.append(f"Missing Referrer-Policy header in initial request or subsequent requests for {params['request']['url']}")

            if message['method'] in ['Network.responseReceivedExtraInfo', 'Network.requestWillBeSentExtraInfo']:
                headers = {k.lower(): v for k, v in params.get('headers', {}).items()}
                if 'content-security-policy' in headers:
                    csp = headers['content-security-policy']
                    if 'unsafe-inline' in csp:
                        flaws.append(f"Content Security Policy Warning: Unsafe inline scripts allowed: {csp} for {params.get('url', 'unknown')}")
                    if 'unsafe-eval' in csp:
                        flaws.append(f"Content Security Policy Warning: Unsafe eval() allowed: {csp} for {params.get('url', 'unknown')}")
                if 'set-cookie' in headers:
                    for cookie in headers['set-cookie'].split(';'):
                        cookie = cookie.strip()
                        if 'httponly' not in cookie.lower():
                            flaws.append(f"Cookie Warning: Missing HttpOnly flag: {cookie}")
                        if 'secure' not in cookie.lower() and params.get('documentURL', '').startswith('https://'):
                            flaws.append(f"Cookie Warning: Missing Secure flag on HTTPS page: {cookie}")
                if 'x-frame-options' not in headers:
                    flaws.append(f"Missing X-Frame-Options header for {params.get('url', 'unknown')}")
                if 'strict-transport-security' not in headers:
                    flaws.append(f"Missing Strict-Transport-Security header for {params.get('url', 'unknown')}")

            if message['method'] == 'Network.responseReceived':
                if 'securityDetails' in params.get('response', {}):
                    security_details = params['response']['securityDetails']
                    if 'validTo' in security_details:
                        valid_to = datetime.datetime.fromtimestamp(security_details['validTo'])
                        current_time = datetime.datetime.now()
                        if valid_to < current_time:
                            flaws.append(f"Certificate Warning: Certificate may be expired: {security_details}")
                    else:
                        flaws.append(f"Certificate Warning: Missing validTo date in security details: {security_details}")
        except json.JSONDecodeError:
            pass
        except KeyError as e:
            pass # Handle cases where expected keys might be missing

    return list(set(flaws)) # Return unique flaws