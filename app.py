# app.py

from flask import Flask, request, jsonify, render_template
import requests
from pysafebrowsing import SafeBrowsing
import whois
from datetime import datetime
import urllib.parse
from urllib.parse import urljoin
from urllib.parse import urlparse
import sys

# IMPORTANT: It is best practice to store sensitive data like API keys
# in environment variables. For this project, you will replace 'YOUR_API_KEY_HERE'
# with your actual Google Safe Browsing API key.
# For demonstration purposes, I will use a placeholder here.
# To deploy, you would use: os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
GOOGLE_SAFE_BROWSING_API_KEY = 'AIzaSyCSAE-iYeJifXQ79LBztI2LiLUF2oHW5Z8'

app = Flask(__name__)

# --- Route to serve the front-end page ---
@app.route('/')
def index():
    return render_template('index.html')

# --- Main Scan Route ---
@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL not provided'}), 400

    scan_results = {'url': url, 'results': []}

    # Normalize URL: Add scheme if missing and handle redirects
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # --- Feature 1 & 5: Unified Connectivity and Server Response Code Check ---
    # This check is now performed first, and its result is used by other features.
    full_response = None
    try:
        # Use GET request for full connectivity and to follow redirects
        full_response = requests.get(url, timeout=10, allow_redirects=True)
        status_code = full_response.status_code
        url = full_response.url  # Update URL to the final redirected URL

        if 200 <= status_code < 300:
            status = 'safe'
            details = f'Successful response: {status_code}. Final URL: {url}'
        elif 300 <= status_code < 400:
            status = 'warning'
            details = f'Redirect detected: {status_code}. Final URL: {url}'
        elif 400 <= status_code < 500:
            status = 'danger'
            details = f'Client-side error: {status_code}'
        else:
            status = 'danger'
            details = f'Server-side error: {status_code}'
        
        scan_results['results'].append({'check': 'Server Response Code', 'status': status, 'details': details})

    except requests.exceptions.RequestException as e:
        scan_results['results'].append({
            'check': 'Server Response Code',
            'status': 'failed',
            'details': f'Could not connect to the URL. Error: {str(e)}'
        })
        # If the request fails, return immediately as other checks won't work.
        return jsonify(scan_results)

    # --- Feature 2: Protocol and SSL/TLS Check ---
    ssl_info = {'check': 'Protocol and SSL/TLS', 'status': 'safe', 'details': 'Site uses HTTPS with a valid certificate.'}
    if not url.startswith('https://'):
        ssl_info['status'] = 'danger'
        ssl_info['details'] = 'Site is not using HTTPS. All traffic is unencrypted.'
    scan_results['results'].append(ssl_info)

    # --- Feature 3: Google Safe Browsing Check (FIXED) ---
    # --- Feature 3: Google Safe Browsing Check (FIXED AGAIN) ---
    safe_browsing_info = {'check': 'Google Safe Browsing', 'status': 'safe', 'details': 'The URL is not on Google\'s list of malicious sites.'}
    if not GOOGLE_SAFE_BROWSING_API_KEY or GOOGLE_SAFE_BROWSING_API_KEY == 'YOUR_API_KEY_HERE':
        safe_browsing_info['status'] = 'warning'
        safe_browsing_info['details'] = 'API key not configured. Safe Browsing check skipped.'
    else:
        try:
            safe_browsing_client = SafeBrowsing(GOOGLE_SAFE_BROWSING_API_KEY)
            result = safe_browsing_client.lookup_urls([url])
            
            # Check for threats directly in the result dictionary
            if result.get(url, {}).get('threats'):
                threats = result[url].get('threats', [])
                threat_types = ", ".join(threats)
                safe_browsing_info['status'] = 'danger'
                safe_browsing_info['details'] = f'This URL is flagged as malicious. Threats: {threat_types}.'
        except Exception as e:
            safe_browsing_info['status'] = 'warning'
            safe_browsing_info['details'] = f'An error occurred during the Safe Browsing check: {str(e)}'
    
    scan_results['results'].append(safe_browsing_info)

    # --- Feature 4: WHOIS and Domain Age Check (FIXED) ---
    domain_age_info = {'check': 'WHOIS and Domain Age', 'status': 'info', 'details': 'WHOIS data could not be retrieved.'}
    try:
        domain_name = urlparse(url).netloc.split(':')[0]
        w = whois.whois(domain_name)
        
        # Check if whois data is valid and not a "no match" response
        if isinstance(w.domain_name, str) and w.creation_date:
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            age_days = (datetime.now() - creation_date).days
            domain_age_info['details'] = f'Domain created on {creation_date.strftime("%Y-%m-%d")}. Age: {age_days} days.'
            
            if age_days < 90:
                domain_age_info['status'] = 'warning'
                domain_age_info['details'] += ' The domain is very young and may be a potential risk.'
            else:
                domain_age_info['status'] = 'safe'
        else:
            domain_age_info['status'] = 'info'
            domain_age_info['details'] = 'WHOIS data for this domain is not publicly available or does not exist (common for subdomains).'
    except Exception as e:
        # Catch various WHOIS-related errors
        domain_age_info['status'] = 'info'
        domain_age_info['details'] = f'An error or "no match" occurred during the WHOIS check. This is common for subdomains or private domains: {str(e)}'
        
    scan_results['results'].append(domain_age_info)
    
    # --- Feature 6: SQL Injection Vulnerability Check ---
    # Logic remains the same as it was correct.
    sqli_info = {'check': 'SQL Injection', 'status': 'safe', 'details': 'No common SQL Injection payloads were detected.'}
    if '?' in url:
        sqli_payloads = ["'", "''", "' OR 1=1--", "1' ORDER BY 1--"]
        error_signatures = ["You have an error in your SQL syntax", "unclosed quotation mark", "supplied argument is not a valid MySQL result"]
        try:
            for payload in sqli_payloads:
                test_url = f"{url}{payload}"
                response = requests.get(test_url, timeout=10)
                if any(sig in response.text for sig in error_signatures):
                    sqli_info['status'] = 'danger'
                    sqli_info['details'] = f"Potential SQL Injection vulnerability found! Payload: '{payload}'"
                    break
        except requests.exceptions.RequestException as e:
            sqli_info['status'] = 'warning'
            sqli_info['details'] = f"Could not perform SQLi check due to a connection error: {str(e)}"
    else:
        sqli_info['status'] = 'info'
        sqli_info['details'] = 'URL does not contain query parameters for testing.'
    scan_results['results'].append(sqli_info)
    
    # --- Feature 7: Basic XSS Vulnerability Check ---
    # Logic remains the same as it was correct.
    xss_info = {'check': 'Cross-Site Scripting (XSS)', 'status': 'safe', 'details': 'No common XSS payloads were reflected in the response.'}
    if '?' in url:
        xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]
        try:
            for payload in xss_payloads:
                test_url = f"{url}{urllib.parse.quote(payload, safe='')}"
                response = requests.get(test_url, timeout=10)
                if payload in response.text:
                    xss_info['status'] = 'danger'
                    xss_info['details'] = f"Potential XSS vulnerability found! Payload: '{payload}' was reflected in the page source."
                    break
        except requests.exceptions.RequestException as e:
            xss_info['status'] = 'warning'
            xss_info['details'] = f"Could not perform XSS check due to a connection error: {str(e)}"
    else:
        xss_info['status'] = 'info'
        xss_info['details'] = 'URL does not contain query parameters for testing.'
    scan_results['results'].append(xss_info)
    
    # --- Feature 8: Robots.txt Analysis ---
    # Logic remains the same as it was correct.
    robots_info = {'check': 'Robots.txt Analysis', 'status': 'safe', 'details': 'Robots.txt exists but does not expose sensitive paths.'}
    try:
        robots_url = urljoin(url, '/robots.txt')
        response = requests.get(robots_url, timeout=10)
        if response.status_code == 200 and 'Disallow' in response.text:
            sensitive_keywords = ['admin', 'login', 'db', 'private']
            if any(keyword in response.text for keyword in sensitive_keywords):
                robots_info['status'] = 'warning'
                robots_info['details'] = 'Sensitive paths found in robots.txt.'
            else:
                robots_info['status'] = 'safe'
                robots_info['details'] = 'Robots.txt exists and does not expose sensitive paths.'
        else:
            robots_info['status'] = 'info'
            robots_info['details'] = 'Robots.txt file not found or is inaccessible.'
    except requests.exceptions.RequestException:
        robots_info['status'] = 'info'
        robots_info['details'] = 'Could not perform robots.txt analysis due to a connection error.'
    scan_results['results'].append(robots_info)

    # --- Feature 9: Technology Detection ---
    # Logic remains the same as it was correct.
    tech_info = {'check': 'Technology Detection', 'status': 'info', 'details': 'No common technologies detected based on headers or page content.'}
    detected_tech = []
    if full_response:
        headers = full_response.headers
        if 'Server' in headers:
            detected_tech.append(f"Server: {headers['Server']}")
        if 'X-Powered-By' in headers:
            detected_tech.append(f"Powered By: {headers['X-Powered-By']}")
        if 'wordpress' in full_response.text.lower():
            detected_tech.append("CMS: WordPress")
        if 'joomla' in full_response.text.lower():
            detected_tech.append("CMS: Joomla")
        if 'drupal' in full_response.text.lower():
            detected_tech.append("CMS: Drupal")
        if detected_tech:
            tech_info['status'] = 'safe'
            tech_info['details'] = f'Detected technologies: {", ".join(detected_tech)}'
    scan_results['results'].append(tech_info)

    # --- Feature 10: Subdomain Enumeration ---
    # Logic remains the same as it was correct.
    subdomain_info = {'check': 'Subdomain Enumeration', 'status': 'info', 'details': 'No common subdomains found.'}
    subdomains = ['www', 'blog', 'api', 'dev', 'test']
    found_subdomains = []
    try:
        domain = urlparse(url).netloc
        for subdomain in subdomains:
            test_subdomain_url = f"http://{subdomain}.{domain}"
            try:
                if requests.head(test_subdomain_url, timeout=5).status_code < 400:
                    found_subdomains.append(test_subdomain_url)
            except requests.exceptions.RequestException:
                pass
    except Exception:
        pass
    if found_subdomains:
        subdomain_info['status'] = 'safe'
        subdomain_info['details'] = f'Found subdomains: {", ".join(found_subdomains)}'
    scan_results['results'].append(subdomain_info)

    return jsonify(scan_results)

if __name__ == '__main__':
    app.run(debug=True,port=5002)