import streamlit as st
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs
from datetime import datetime
import ssl
import socket
import re
import json
import pandas as pd
from typing import Dict, List, Tuple, Optional, Any, Union

# --- Constants ---
GDPR_CHECKS = {
    "HTTPS_Enabled": {
        "title": "HTTPS Enabled",
        "description": "Verifies if the website uses HTTPS for secure communication.",
        "recommendation": "Enable HTTPS by obtaining an SSL/TLS certificate from a trusted Certificate Authority (CA)."
    },
    "Cookie_Consent_Banner": {
        "title": "Cookie Consent Banner",
        "description": "Checks for the presence of a cookie consent banner.",
        "recommendation": "Implement a cookie consent banner that complies with GDPR requirements."
    },
    "Privacy_Policy_Link": {
        "title": "Privacy Policy Link",
        "description": "Verifies if a link to the privacy policy is present.",
        "recommendation": "Add a clear and easily accessible link to your privacy policy."
    },
    "Security_Headers": {
        "title": "Security Headers",
        "description": "Checks for important security headers.",
        "recommendation": "Implement security headers like Content-Security-Policy, X-Content-Type-Options, etc."
    },
    "Cookie_Attributes": {
        "title": "Cookie Attributes",
        "description": "Verifies if cookies have secure and httpOnly flags.",
        "recommendation": "Set Secure, HttpOnly, and SameSite attributes on cookies."
    },
    "DSAR_Endpoints": {
        "title": "DSAR Endpoints",
        "description": "Checks for Data Subject Access Request (DSAR) endpoints.",
        "recommendation": "Implement DSAR endpoints as required by GDPR."
    }
}

# Known tracking domains
TRACKING_DOMAINS = {
    'google-analytics.com', 'googletagmanager.com', 'facebook.net',
    'doubleclick.net', 'googleadservices.com', 'hotjar.com',
    'hubspot.com', 'linkedin.com', 'twitter.com', 'youtube.com'
}

# Common CMP (Consent Management Platform) selectors
CMP_SELECTORS = [
    '#onetrust-banner-sdk',
    '.cookie-banner',
    '#cookie-banner',
    '.cc-banner',
    '.gdpr-banner',
    '#cookie-notice',
    '.cookie-notice',
    '#cc-banner',
    '#cookie-consent',
    '.cookie-consent'
]

# --- Helper Functions ---
def get_website_content(url: str) -> Tuple[Optional[requests.Response], Optional[BeautifulSoup]]:
    """Fetch website content and parse with BeautifulSoup."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        response = requests.get(url, headers=headers, timeout=10, verify=True)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        return response, soup
    except Exception as e:
        st.error(f"Error fetching website content: {str(e)}")
        return None, None

def check_https(url: str) -> Tuple[bool, str]:
    """Check if website uses HTTPS and has valid SSL certificate."""
    try:
        parsed = urlparse(url)
        if not parsed.scheme:
            url = f'https://{url}'
            parsed = urlparse(url)
        
        if parsed.scheme != 'https':
            return False, "Website is not using HTTPS"
        
        # Check SSL certificate
        hostname = parsed.hostname
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                # Check certificate expiration
                cert_expiry = ssl.cert_time_to_seconds(cert['notAfter'])
                current_time = datetime.now().timestamp()
                if cert_expiry < current_time:
                    return False, "SSL certificate has expired"
                
                # Check if certificate is valid for the domain
                cert_domains = []
                for name in cert.get('subjectAltName', []):
                    if name[0] == 'DNS':
                        cert_domains.append(name[1].lower())
                
                if not any(hostname.endswith(domain.lstrip('*.')) for domain in cert_domains):
                    return False, f"SSL certificate not valid for domain {hostname}"
        
        return True, "HTTPS is properly configured with a valid SSL certificate"
    except ssl.SSLError as e:
        return False, f"SSL Error: {str(e)}"
    except socket.timeout:
        return False, "Connection timed out while checking SSL certificate"
    except Exception as e:
        return False, f"Error checking HTTPS: {str(e)}"

def check_cookie_banner(soup: BeautifulSoup, response_text: str) -> Tuple[bool, str]:
    """Check for common cookie consent banner patterns and common consent management platforms."""
    try:
        # Check for common CMP selectors in HTML
        for selector in CMP_SELECTORS:
            if soup.select(selector):
                return True, f"Found cookie banner with selector: {selector}"
        
        # Check for common CMP iframes
        for iframe in soup.find_all('iframe', src=True):
            if any(cmp in iframe['src'].lower() for cmp in ['cookie', 'consent', 'privacy', 'gdpr', 'trustarc', 'onetrust', 'cookiebot']):
                return True, f"Found potential CMP iframe: {iframe['src']}"
        
        # Check for common CMP scripts
        for script in soup.find_all('script', src=True):
            if any(cmp in script['src'].lower() for cmp in ['cookie', 'consent', 'privacy', 'gdpr', 'trustarc', 'onetrust', 'cookiebot']):
                return True, f"Found potential CMP script: {script['src']}"
        
        # Check for common CMP text in page content
        cookie_keywords = [
            'cookie consent', 'cookie notice', 'cookie banner', 'gdpr compliance',
            'privacy settings', 'manage cookies', 'consent manager', 'cookie settings',
            'we use cookies', 'this site uses cookies', 'by continuing to browse',
            'we value your privacy'
        ]
        
        page_text = soup.get_text(' ', strip=True).lower()
        if any(keyword in page_text for keyword in cookie_keywords):
            return True, "Found cookie-related text in page content"
        
        return False, "No standard cookie consent banner or CMP detected"
    except Exception as e:
        return False, f"Error checking for cookie banner: {str(e)}"

def check_privacy_policy(soup: BeautifulSoup, base_url: str) -> Tuple[bool, str]:
    """Check for privacy policy link in the page."""
    try:
        privacy_terms = ['privacy', 'datenschutz', 'confidentiality', 'gdpr']
        links = soup.find_all('a', href=True)
        
        for link in links:
            href = link.get('href', '').lower()
            text = link.get_text().lower()
            
            if any(term in href + text for term in privacy_terms):
                privacy_url = urljoin(base_url, href)
                return True, f"Found privacy policy link: {privacy_url}"
                
        return False, "No privacy policy link found"
    except Exception as e:
        return False, f"Error checking for privacy policy: {str(e)}"

def check_security_headers(response: requests.Response) -> Dict[str, Any]:
    """Check for important security headers."""
    try:
        security_headers = {
            'Content-Security-Policy': {
                'present': False,
                'value': None,
                'recommendation': 'Implement Content-Security-Policy header to prevent XSS attacks'
            },
            'X-Content-Type-Options': {
                'present': False,
                'value': None,
                'recommendation': 'Set X-Content-Type-Options: nosniff to prevent MIME type sniffing'
            },
            'X-Frame-Options': {
                'present': False,
                'value': None,
                'recommendation': 'Set X-Frame-Options to prevent clickjacking attacks'
            },
            'Strict-Transport-Security': {
                'present': False,
                'value': None,
                'recommendation': 'Implement HSTS with Strict-Transport-Security header'
            },
            'X-XSS-Protection': {
                'present': False,
                'value': None,
                'recommendation': 'Set X-XSS-Protection header for legacy browsers'
            }
        }
        
        headers = response.headers
        for header in security_headers:
            if header in headers:
                security_headers[header]['present'] = True
                security_headers[header]['value'] = headers[header]
        
        return security_headers
    except Exception as e:
        return {}

def check_cookies(response: requests.Response) -> Tuple[bool, List[Dict]]:
    """Check cookies for secure and httpOnly flags."""
    try:
        cookies = []
        if 'set-cookie' in response.headers:
            cookie_headers = response.headers.get_list('set-cookie')
            for cookie in cookie_headers:
                cookie_data = {'name': cookie.split(';')[0].split('=')[0].strip()}
                cookie_data['secure'] = 'secure' in cookie.lower()
                cookie_data['httpOnly'] = 'httponly' in cookie.lower()
                cookie_data['samesite'] = 'samesite' in cookie.lower()
                cookies.append(cookie_data)
        
        if not cookies:
            return False, []
            
        all_secure = all(c.get('secure', False) for c in cookies)
        all_http_only = all(c.get('httpOnly', False) for c in cookies)
        
        return all_secure and all_http_only, cookies
    except Exception as e:
        return False, []

def check_dsar_endpoints(soup: BeautifulSoup, base_url: str) -> Tuple[bool, List[str]]:
    """Check for common DSAR (Data Subject Access Request) endpoints."""
    try:
        dsar_terms = ['dsar', 'data subject', 'gdpr request', 'right to be forgotten', 'data access', 'privacy request']
        dsar_links = []
        
        for link in soup.find_all('a', href=True):
            href = link.get('href', '').lower()
            text = link.get_text().lower()
            
            if any(term in href + text for term in dsar_terms):
                dsar_url = urljoin(base_url, href)
                dsar_links.append(dsar_url)
        
        return len(dsar_links) > 0, dsar_links
    except Exception as e:
        return False, []

def check_third_party_requests(response: requests.Response, soup: BeautifulSoup) -> Dict[str, List[str]]:
    """Check for third-party trackers and external resources."""
    try:
        trackers = {
            'google_analytics': [],
            'facebook': [],
            'twitter': [],
            'linkedin': [],
            'hotjar': [],
            'other_trackers': []
        }
        
        # Check for common tracking scripts
        for script in soup.find_all('script', src=True):
            src = script['src'].lower()
            if 'googletagmanager.com' in src or 'google-analytics.com' in src:
                trackers['google_analytics'].append(src)
            elif 'facebook.net' in src or 'connect.facebook.net' in src:
                trackers['facebook'].append(src)
            elif 'platform.twitter.com' in src or 'twimg.com' in src:
                trackers['twitter'].append(src)
            elif 'linkedin.com' in src or 'licdn.com' in src:
                trackers['linkedin'].append(src)
            elif 'hotjar.com' in src:
                trackers['hotjar'].append(src)
            elif any(domain in src for domain in ['doubleclick.net', 'addthis.com', 'addtoany.com', 'sharethis.com']):
                trackers['other_trackers'].append(src)
        
        # Check for tracking iframes
        for iframe in soup.find_all('iframe', src=True):
            src = iframe['src'].lower()
            if any(domain in src for domain in ['doubleclick.net', 'facebook.com/plugins', 'youtube.com/embed']):
                trackers['other_trackers'].append(f"iframe: {src}")
        
        # Check for tracking pixels
        for img in soup.find_all('img', src=True):
            src = img['src'].lower()
            if any(domain in src for domain in ['pixel.quantserve.com', 'pixel.facebook.com', 'analytics.twitter.com']):
                trackers['other_trackers'].append(f"pixel: {src}")
        
        return {k: v for k, v in trackers.items() if v}
    except Exception as e:
        st.error(f"Error checking third-party trackers: {str(e)}")
        return {}

def check_privacy_policy_content(soup: BeautifulSoup, privacy_url: str) -> Dict[str, bool]:
    """Check privacy policy content for important GDPR sections."""
    try:
        text = soup.get_text(' ', strip=True).lower()
        return {
            'data_collection': any(term in text for term in ['what data we collect', 'data we collect', 'collection of personal data']),
            'data_usage': any(term in text for term in ['how we use your data', 'use of personal data', 'purpose of processing']),
            'data_sharing': any(term in text for term in ['sharing your data', 'third-party sharing', 'data processors']),
            'user_rights': any(term in text for term in ['your rights', 'right to access', 'right to be forgotten', 'right to erasure', 'data subject rights']),
            'cookies': 'cookie' in text or 'cookies' in text,
            'security': any(term in text for term in ['data security', 'security measures', 'protect your data']),
            'contact_dpo': any(term in text for term in ['data protection officer', 'contact us', 'dpo@', 'privacy@']),
            'international_transfers': any(term in text for term in ['international transfers', 'data transfers outside', 'eu-us privacy shield']),
            'data_retention': any(term in text for term in ['data retention', 'how long we keep', 'retention period']),
            'updates': any(term in text for term in ['changes to this policy', 'policy updates', 'last updated'])
        }
    except Exception as e:
        st.error(f"Error analyzing privacy policy content: {str(e)}")
        return {}

def check_csp_header(response: requests.Response) -> Dict[str, Any]:
    """Analyze Content Security Policy header."""
    try:
        csp_header = response.headers.get('Content-Security-Policy', '').lower()
        if not csp_header:
            return {'present': False, 'score': 0, 'issues': ['No CSP header found']}
        
        directives = {}
        issues = []
        score = 0
        
        # Parse CSP directives
        for directive in csp_header.split(';'):
            directive = directive.strip()
            if ' ' in directive:
                name, *values = directive.split()
                directives[name] = [v.strip("'\"") for v in values]
        
        # Check for unsafe-inline and unsafe-eval
        for directive, values in directives.items():
            if 'unsafe-inline' in values and 'nonce-' not in ' '.join(values) and 'sha256-' not in ' '.join(values):
                issues.append(f"{directive} contains 'unsafe-inline' without nonce or hash")
            if 'unsafe-eval' in values:
                issues.append(f"{directive} contains 'unsafe-eval'")
        
        # Check for missing important directives
        important_directives = ['default-src', 'script-src', 'style-src', 'img-src', 'connect-src']
        missing = [d for d in important_directives if d not in directives]
        if missing:
            issues.append(f"Missing important CSP directives: {', '.join(missing)}")
        
        # Calculate score (0-100)
        present_directives = len([d for d in important_directives if d in directives])
        score = int((present_directives / len(important_directives)) * 100)
        
        return {
            'present': True,
            'score': score,
            'issues': issues,
            'directives': {k: v for k, v in directives.items() if k in important_directives}
        }
    except Exception as e:
        return {'present': False, 'score': 0, 'issues': [f'Error parsing CSP: {str(e)}']}

def check_ndpr_compliance(soup: BeautifulSoup, response: requests.Response, url: str) -> Dict:
    """Check for NDPR (Nigeria Data Protection Regulation) compliance."""
    results = {
        'data_protection_officer': False,
        'data_processing_notice': False,
        'data_subject_rights': False,
        'data_breach_protocol': False,
        'data_transfer_outside_nigeria': False,
        'data_minimization': False,
        'purpose_limitation': False,
        'data_accuracy': False,
        'storage_limitation': False,
        'accountability': False,
        'lawful_basis': False,
        'consent_management': False
    }
    
    text = soup.get_text().lower()
    html = str(soup).lower()
    
    # 1. Data Protection Officer/Representative
    dpo_indicators = [
        'data protection officer', 'dpo', 
        'data protection compliance organization', 'dpco',
        'nigerian data protection', 'ndpr',
        'data protection representative',
        'contact@.*data.*protection', 'dpo@', 'privacy@'
    ]
    results['data_protection_officer'] = any(re.search(indicator, text) for indicator in dpo_indicators)
    
    # 2. Data Processing Notice
    notice_indicators = [
        'lawful basis for processing', 'purpose of processing', 
        'data processing notice', 'how we use your data',
        'why we process your data', 'legal basis for processing',
        'purpose of data collection', 'data collection notice'
    ]
    results['data_processing_notice'] = any(indicator in text for indicator in notice_indicators)
    
    # 3. Data Subject Rights
    rights_indicators = [
        'right to access', 'right to rectification', 
        'right to erasure', 'right to be forgotten',
        'right to restrict processing', 'right to data portability', 
        'right to object', 'rights in relation to automated decision making',
        'data subject rights', 'your privacy rights',
        'how to access your data', 'how to delete your data',
        'how to update your information'
    ]
    results['data_subject_rights'] = any(indicator in text for indicator in rights_indicators)
    
    # 4. Data Breach Protocol
    breach_indicators = [
        'data breach', 'personal data breach', 
        'breach notification', '72 hours',
        'data security incident', 'personal data incident',
        'report a data breach', 'breach response plan',
        'data breach procedure', 'incident response'
    ]
    results['data_breach_protocol'] = any(indicator in text for indicator in breach_indicators)
    
    # 5. Data Transfer Outside Nigeria
    transfer_indicators = [
        'cross-border data transfer', 'data transfer outside nigeria', 
        'international data transfer', 'data transfer to other countries',
        'data transfer outside your country', 'data localization',
        'data residency', 'data sovereignty',
        'data transfer agreement', 'standard contractual clauses',
        'binding corporate rules'
    ]
    results['data_transfer_outside_nigeria'] = any(indicator in text for indicator in transfer_indicators)
    
    # 6. Data Minimization
    minimization_indicators = [
        'data minimization', 'collect only necessary data',
        'minimum data collection', 'collect only what we need',
        'limit data collection', 'purpose limitation'
    ]
    results['data_minimization'] = any(indicator in text for indicator in minimization_indicators)
    
    # 7. Purpose Limitation
    purpose_indicators = [
        'purpose limitation', 'specific purpose for data',
        'use data only for stated purpose', 'not use data for other purposes',
        'data usage limitations'
    ]
    results['purpose_limitation'] = any(indicator in text for indicator in purpose_indicators)
    
    # 8. Data Accuracy
    accuracy_indicators = [
        'data accuracy', 'keep data accurate',
        'update your information', 'correct inaccurate data',
        'data rectification', 'ensure data is up to date'
    ]
    results['data_accuracy'] = any(indicator in text for indicator in accuracy_indicators)
    
    # 9. Storage Limitation
    storage_indicators = [
        'storage limitation', 'data retention period',
        'how long we keep your data', 'data retention policy',
        'delete data when no longer needed', 'data disposal',
        'data retention schedule'
    ]
    results['storage_limitation'] = any(indicator in text for indicator in storage_indicators)
    
    # 10. Accountability
    accountability_indicators = [
        'data protection by design', 'data protection by default',
        'privacy by design', 'privacy impact assessment',
        'data protection impact assessment', 'dpia',
        'data protection policies', 'privacy policies',
        'data protection training', 'employee training on data protection'
    ]
    results['accountability'] = any(indicator in text for indicator in accountability_indicators)
    
    # 11. Lawful Basis for Processing
    lawful_basis_indicators = [
        'lawful basis', 'legal basis for processing',
        'consent', 'contractual necessity',
        'legal obligation', 'vital interests',
        'public task', 'legitimate interests'
    ]
    results['lawful_basis'] = any(indicator in text for indicator in lawful_basis_indicators)
    
    # 12. Consent Management
    consent_indicators = [
        'consent management', 'withdraw consent',
        'manage your preferences', 'update your preferences',
        'opt-out', 'unsubscribe',
        'marketing preferences', 'communication preferences'
    ]
    results['consent_management'] = any(indicator in text for indicator in consent_indicators)
    
    # Check for consent management in forms
    if not results['consent_management']:
        # Look for checkboxes or toggles that might indicate consent
        if ('<input type="checkbox"' in html and 
            any(term in html for term in ['consent', 'agree', 'accept', 'terms'])):
            results['consent_management'] = True
    
    return results

def run_gdpr_audit(url: str) -> Dict:
    """Run all GDPR and NDPR compliance checks."""
    results = {}
    
    try:
        # Get website content
        response, soup = get_website_content(url)
        if not response or not soup:
            return {}
        
        # Run basic GDPR checks
        results['gdpr'] = {}
        results['gdpr']['https'] = check_https(url)
        results['gdpr']['cookie_banner'] = check_cookie_banner(soup, response.text)
        results['gdpr']['privacy_policy'] = check_privacy_policy(soup, url)
        results['gdpr']['security_headers'] = check_security_headers(response)
        results['gdpr']['cookies'] = check_cookies(response)
        results['gdpr']['dsar_endpoints'] = check_dsar_endpoints(soup, url)
        
        # Run advanced GDPR checks
        results['gdpr']['third_party_trackers'] = check_third_party_requests(response, soup)
        results['gdpr']['csp_analysis'] = check_csp_header(response)
        
        # Run NDPR compliance checks with the URL parameter
        results['ndpr'] = check_ndpr_compliance(soup, response, url)
        
        # If privacy policy link was found, analyze its content
        if results['gdpr']['privacy_policy'][0]:
            privacy_url = results['gdpr']['privacy_policy'][1].split('Found privacy policy link: ')[-1]
            try:
                privacy_response, privacy_soup = get_website_content(privacy_url)
                if privacy_response and privacy_soup:
                    results['gdpr']['privacy_policy_content'] = check_privacy_policy_content(privacy_soup, privacy_url)
                    
                    # Also check NDPR compliance in the privacy policy
                    ndpr_privacy = check_ndpr_compliance(privacy_soup, privacy_response, privacy_url)
                    # Merge with existing NDPR results
                    for key, value in ndpr_privacy.items():
                        if key not in results['ndpr'] or not results['ndpr'][key]:
                            results['ndpr'][key] = value
                            
            except Exception as e:
                st.error(f"Error analyzing privacy policy content: {str(e)}")
        
        return results
    except Exception as e:
        st.error(f"Error running compliance audit: {str(e)}")
        return {}

def display_results(results: Dict, url: str):
    """Display the research findings and compliance results in an academic paper format."""
    
    # Custom CSS for academic paper styling
    st.markdown("""
    <style>
    .title {
        font-size: 24px;
        font-weight: bold;
        text-align: center;
        margin: 20px 0;
    }
    .section-header {
        font-size: 20px;
        font-weight: bold;
        margin: 15px 0 10px 0;
        border-bottom: 1px solid #ddd;
        padding-bottom: 5px;
    }
    .subsection {
        margin-left: 20px;
        margin-bottom: 15px;
    }
    .subsection-header {
        font-weight: bold;
        margin: 10px 0 5px 0;
    }
    .toc {
        background-color: #f8f9fa;
        padding: 15px;
        border-radius: 5px;
        margin: 15px 0;
    }
    .toc-header {
        font-weight: bold;
        margin-bottom: 10px;
    }
    .toc-item {
        margin: 5px 0;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Title Page
    st.markdown("<div class='title'>Privacy Concerns in HealthTech Applications in Nigeria</div>", unsafe_allow_html=True)
    st.markdown("<div style='text-align: center; margin-bottom: 30px;'>An Investigative Study Combining Policy Analysis and Technical Evaluation</div>", unsafe_allow_html=True)
    
    # Table of Contents
    toc_html = """
    <div class='toc'>
        <div class='toc-header'>Table of Contents</div>
        <div class='toc-item'>1.0 Introduction and Overview</div>
        <div class='toc-item'>2.0 Progress to Date</div>
        <div class='toc-item'>3.0 Planned Work</div>
        <div class='toc-item'>4.0 Compliance Assessment Tool</div>
    </div>
    """
    st.markdown(toc_html, unsafe_allow_html=True)
    
    # Section 1: Introduction and Overview
    with st.expander("1.0 Introduction and Overview", expanded=True):
        st.markdown("### 1.1 Research Question and Methodological Framework")
        st.write("This study investigates the privacy implications of HealthTech applications in Nigeria, "
                "evaluating both policy frameworks and technical implementations to identify gaps and "
                "recommend improvements in data protection practices.")
        
        st.markdown("### 1.2 Specific Research Objectives and Scope")
        st.write("""
        - Analyze existing privacy policies and data protection measures in Nigerian HealthTech
        - Evaluate technical implementations of privacy controls
        - Assess compliance with NDPR and other relevant regulations
        - Provide actionable recommendations for improvement
        """)
        
        st.markdown("### 1.3 Technical Investigation Design and Tools")
        st.write("The technical evaluation utilizes automated scanning tools, manual inspection, "
                "and policy analysis to assess compliance across multiple dimensions.")
    
    # Section 2: Progress to Date
    with st.expander("2.0 Progress to Date"):
        st.markdown("### 2.1 Literature Review and Theoretical Foundation")
        st.write("Comprehensive review of existing research on HealthTech privacy, data protection "
                "frameworks, and regulatory requirements in Nigeria.")
        
        st.markdown("### 2.2 Policy Analysis and Regulatory Framework")
        st.write("Evaluation of NDPR compliance and comparison with international standards "
                "like GDPR.")
        
        st.markdown("### 2.3 Technical Evaluation Progress")
        st.write("Initial technical assessments have been conducted on multiple HealthTech platforms "
                "using the tool below.")
        
    # Section 3: Planned Work
    with st.expander("3.0 Planned Work"):
        st.markdown("### 3.1 Technical Evaluation Completion")
        st.write("Finalize automated scanning and manual verification processes.")
        
        st.markdown("### 3.2 Stakeholder Engagement")
        st.write("Engage with HealthTech providers, regulators, and users for validation.")
        
        st.markdown("### 3.3 Integrated Analysis")
        st.write("Synthesize findings across technical and policy dimensions.")
    
    # Section 4: Compliance Assessment Tool
    st.markdown("## 4.0 Compliance Assessment Tool")
    st.write("Use the tool below to evaluate compliance of any HealthTech application.")
    
    # Add a horizontal line before the tool
    st.markdown("---")
    
    # Show the URL being analyzed
    st.write(f"### Analyzing: {url}")
    
    if not results:
        st.write("No results to display. The website might be unreachable or the audit failed.")
        return
    
    # Custom CSS for neutral styling
    st.markdown("""
    <style>
        .main-title { 
            font-size: 2rem !important; 
            font-weight: 600; 
            margin-bottom: 1rem;
            color: #333;
        }
        .section-title { 
            font-size: 1.5rem !important; 
            font-weight: 500; 
            margin: 1.5rem 0 1rem 0;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #e0e0e0;
            color: #333;
        }
        .check-card { 
            border-left: 4px solid #666; 
            padding: 0.75rem; 
            margin: 0.5rem 0; 
            border-radius: 0.25rem;
            background-color: #f8f9fa;
        }
        .passed { font-weight: 500; }
        .failed { font-weight: 500; }
        .warning { font-weight: 500; }
        .info-box { 
            padding: 1rem; 
            border-radius: 0.25rem;
            margin: 0.5rem 0;
            background-color: #f5f5f5;
            border: 1px solid #e0e0e0;
        }
        .tab-content {
            padding: 1rem 0;
        }
        .stTabs [data-baseweb="tab-list"] {
            gap: 0.5rem;
            margin-bottom: 1rem;
            border-bottom: 1px solid #e0e0e0;
        }
        .stTabs [data-baseweb="tab"] {
            padding: 0.5rem 1rem;
            border-radius: 0.25rem;
            border: 1px solid transparent;
        }
        .stTabs [aria-selected="true"] {
            background-color: #f0f0f0;
            border-color: #ccc;
        }
        .metric-value {
            font-size: 1.5rem;
            font-weight: 600;
            color: #333;
        }
        .metric-label {
            font-size: 0.875rem;
            color: #666;
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Header
    st.markdown(f'<div class="main-title">Compliance Report</div>', unsafe_allow_html=True)
    
    # Website info
    st.caption(f"Audit performed on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    st.code(f"{url}", language="text")
    
    # Create tabs for different compliance sections
    tab1, tab2, tab3, tab4 = st.tabs([
        "Overview", "GDPR", "NDPR", "Technical"
    ])
    
    with tab1:
        st.markdown("### Compliance Overview")
        
        # GDPR Summary
        st.markdown("#### GDPR Compliance")
        gdpr = results.get('gdpr', {})
        gdpr_checks = [
            ("HTTPS & SSL", gdpr.get('https', [False])[0]),
            ("Cookie Consent", gdpr.get('cookie_banner', [False])[0]),
            ("Privacy Policy", gdpr.get('privacy_policy', [False])[0]),
            ("Security Headers", bool(gdpr.get('security_headers', {}))),
            ("DSAR Endpoints", gdpr.get('dsar_endpoints', [False])[0])
        ]
        
        for check, passed in gdpr_checks:
            status = "✓" if passed else "✗"
            st.markdown(f"- {status} {check}")
        
        # NDPR Summary
        st.markdown("\n#### NDPR Compliance")
        ndpr = results.get('ndpr', {})
        ndpr_checks = [
            ("Data Protection Officer", ndpr.get('data_protection_officer', False)),
            ("Data Processing Notice", ndpr.get('data_processing_notice', False)),
            ("Data Subject Rights", ndpr.get('data_subject_rights', False)),
            ("Data Breach Protocol", ndpr.get('data_breach_protocol', False)),
            ("Data Transfer Notice", ndpr.get('data_transfer_outside_nigeria', False)),
            ("Data Minimization", ndpr.get('data_minimization', False)),
            ("Purpose Limitation", ndpr.get('purpose_limitation', False)),
            ("Data Accuracy", ndpr.get('data_accuracy', False)),
            ("Storage Limitation", ndpr.get('storage_limitation', False)),
            ("Accountability", ndpr.get('accountability', False)),
            ("Lawful Basis", ndpr.get('lawful_basis', False)),
            ("Consent Management", ndpr.get('consent_management', False))
        ]
        
        for check, passed in ndpr_checks:
            status = "✓" if passed else "✗"
            st.markdown(f"- {status} {check}")
    
    with tab2:
        st.markdown("### GDPR Compliance Details")
        gdpr = results.get('gdpr', {})
        
        # HTTPS Check
        https_issue = None
        with st.expander("HTTPS & SSL"):
            if gdpr.get('https', [False])[0]:
                st.markdown("✓ Website uses HTTPS with a valid SSL certificate.")
            else:
                st.markdown("✗ Website does not use HTTPS or has SSL issues.")
                https_issue = "https"
        
        # Show HTTPS solution if needed
        if https_issue:
            show_javascript_solution(https_issue)
        
        # Cookie Banner Check
        cookie_issue = None
        with st.expander("Cookie Consent"):
            if gdpr.get('cookie_banner', [False])[0]:
                st.markdown("✓ Cookie consent banner detected.")
            else:
                st.markdown("✗ No cookie consent banner detected or it may not be compliant.")
                cookie_issue = "cookie_banner"
        
        # Show cookie banner solution if needed
        if cookie_issue:
            show_javascript_solution(cookie_issue)
                
        # Privacy Policy Check
        with st.expander("Privacy Policy"):
            if gdpr.get('privacy_policy', [False])[0]:
                st.markdown(f"✓ {gdpr['privacy_policy'][1]}")
                if 'privacy_policy_content' in gdpr:
                    st.markdown("\n**Policy Content Analysis:**")
                    for section, present in gdpr['privacy_policy_content'].items():
                        status = "✓" if present else "✗"
                        st.markdown(f"- {status} {section}")
            else:
                st.markdown("✗ No privacy policy link found or it's not easily accessible.")
                show_javascript_solution("privacy_policy")
        
        # Security Headers
        with st.expander("Security Headers"):
            headers = gdpr.get('security_headers', {})
            if headers:
                st.markdown("**Security Headers:**")
                for header, status in headers.items():
                    check_mark = "\u2713"  # ✓
                    x_mark = "\u2717"      # ✗
                    st.markdown(f"- {check_mark if status['present'] else x_mark} {header}: {status.get('value', 'Not found')}")
            else:
                st.markdown("No security headers information available.")
        
        # DSAR Endpoints
        with st.expander("DSAR Endpoints"):
            if gdpr.get('dsar_endpoints', [False])[0]:
                st.markdown(f"✓ {gdpr['dsar_endpoints'][1]}")
            else:
                st.markdown("✗ No clear DSAR (Data Subject Access Request) endpoints found.")
        
        # Third-party Trackers
        with st.expander("Third-party Trackers"):
            trackers = gdpr.get('third_party_trackers', {})
            if trackers.get('count', 0) > 0:
                st.markdown(f"⚠️ Found {trackers['count']} potential third-party trackers:")
                for tracker in trackers.get('domains', [])[:10]:  # Show first 10
                    st.markdown(f"- {tracker}")
                if trackers['count'] > 10:
                    st.markdown(f"... and {trackers['count'] - 10} more")
            else:
                st.markdown("✓ No third-party trackers detected.")
    
    with tab3:
        st.markdown("### NDPR Compliance Details")
        ndpr = results.get('ndpr', {})
        
        # Data Protection Officer
        with st.expander("1. Data Protection Officer"):
            if ndpr.get('data_protection_officer', False):
                st.markdown("✓ Found information about a Data Protection Officer or point of contact.")
            else:
                st.markdown("✗ No clear information found about a Data Protection Officer or point of contact.")
                st.markdown("**Recommendation:** Appoint a Data Protection Officer (DPO) and provide their contact information.")
        
        # Data Processing Notice
        with st.expander("2. Data Processing Notice"):
            if ndpr.get('data_processing_notice', False):
                st.markdown("✓ Found data processing notice explaining lawful basis for processing.")
            else:
                st.markdown("✗ No clear data processing notice found explaining the lawful basis for processing.")
                st.markdown("**Recommendation:** Clearly state the legal basis for processing personal data.")
        
        # Data Subject Rights
        with st.expander("3. Data Subject Rights"):
            if ndpr.get('data_subject_rights', False):
                st.markdown("✓ Found information about data subject rights under NDPR.")
            else:
                st.markdown("✗ No clear information found about data subject rights under NDPR.")
                st.markdown("**Recommendation:** Clearly explain users' rights regarding their personal data.")
        
        # Data Breach Protocol
        with st.expander("4. Data Breach Protocol"):
            if ndpr.get('data_breach_protocol', False):
                st.markdown("✓ Found information about data breach notification procedures.")
            else:
                st.markdown("✗ No clear information found about data breach notification procedures.")
                st.markdown("**Recommendation:** Implement and document a data breach response plan.")
        
        # Data Transfer Outside Nigeria
        with st.expander("5. Cross-border Data Transfer"):
            if ndpr.get('data_transfer_outside_nigeria', False):
                st.markdown("✓ Found information about cross-border data transfers.")
            else:
                st.markdown("✗ No clear information found about cross-border data transfers.")
                st.markdown("**Recommendation:** Disclose if and how data is transferred outside Nigeria.")
        
        # Data Minimization
        with st.expander("6. Data Minimization"):
            if ndpr.get('data_minimization', False):
                st.markdown("✓ Appears to follow data minimization principles.")
            else:
                st.markdown("✗ Potential data collection beyond what's necessary detected.")
                st.markdown("**Recommendation:** Review and limit data collection to what's strictly necessary.")
        
        # Purpose Limitation
        with st.expander("7. Purpose Limitation"):
            if ndpr.get('purpose_limitation', False):
                st.markdown("✓ Clear purpose for data collection and processing stated.")
            else:
                st.markdown("✗ Purpose of data collection not clearly stated or seems overly broad.")
                st.markdown("**Recommendation:** Clearly define and limit the purposes of data processing.")
        
        # Data Accuracy
        with st.expander("8. Data Accuracy"):
            if ndpr.get('data_accuracy', False):
                st.markdown("✓ Has measures to ensure data accuracy.")
            else:
                st.markdown("✗ No clear process for maintaining data accuracy.")
                st.markdown("**Recommendation:** Implement processes to keep personal data accurate and up-to-date.")
        
        # Storage Limitation
        with st.expander("9. Storage Limitation"):
            if ndpr.get('storage_limitation', False):
                st.markdown("✓ Has defined data retention periods.")
            else:
                st.markdown("✗ No clear data retention policy found.")
                st.markdown("**Recommendation:** Define and implement data retention periods.")
        
        # Accountability
        with st.expander("10. Accountability"):
            if ndpr.get('accountability', False):
                st.markdown("✓ Demonstrates accountability measures.")
            else:
                st.markdown("✗ Insufficient evidence of accountability measures.")
                st.markdown("**Recommendation:** Implement and document accountability measures.")
        
        # Lawful Basis
        with st.expander("11. Lawful Basis for Processing"):
            if ndpr.get('lawful_basis', False):
                st.markdown("✓ Clearly states lawful basis for processing.")
            else:
                st.markdown("✗ Lawful basis for processing not clearly stated.")
                st.markdown("**Recommendation:** Clearly specify the legal basis for processing personal data.")
        
        # Consent Management
        with st.expander("12. Consent Management"):
            if ndpr.get('consent_management', False):
                st.markdown("✓ Proper consent management mechanisms in place.")
            else:
                st.markdown("✗ Issues with consent management detected.")
                st.markdown("**Recommendation:** Implement proper consent collection and management processes.")
        
        # Data Protection Impact Assessment
        with st.expander("13. Data Protection Impact Assessment"):
            if ndpr.get('dpia', False):
                st.markdown("✓ Evidence of Data Protection Impact Assessments.")
            else:
                st.markdown("✗ No evidence of Data Protection Impact Assessments.")
                st.markdown("**Recommendation:** Conduct DPIAs for high-risk processing activities.")
        
        # Data Protection by Design
        with st.expander("14. Data Protection by Design"):
            if ndpr.get('privacy_by_design', False):
                st.markdown("✓ Evidence of privacy by design principles.")
            else:
                st.markdown("✗ Limited evidence of privacy by design implementation.")
                st.markdown("**Recommendation:** Implement privacy by design and by default.")
        
        # Data Protection Training
        with st.expander("15. Staff Training"):
            if ndpr.get('staff_training', False):
                st.markdown("✓ Evidence of staff data protection training.")
            else:
                st.markdown("✗ No evidence of staff data protection training.")
                st.markdown("**Recommendation:** Provide regular data protection training to staff.")
        
        # Additional NDPR Checks
        with st.expander("Data Protection Principles"):
            status = "✓" if ndpr.get('data_minimization', False) else "✗"
            st.markdown(f"**Data Minimization:** {status} Collecting only necessary data")
            status = "✓" if ndpr.get('purpose_limitation', False) else "✗"
            st.markdown(f"**Purpose Limitation:** {status} Clear purpose for data collection")
            status = "✓" if ndpr.get('data_accuracy', False) else "✗"
            st.markdown(f"**Data Accuracy:** {status} Processes to ensure data accuracy")
            status = "✓" if ndpr.get('storage_limitation', False) else "✗"
            st.markdown(f"**Storage Limitation:** {status} Defined data retention periods")
            status = "✓" if ndpr.get('accountability', False) else "✗"
            st.markdown(f"**Accountability:** {status} Evidence of data protection measures")
            status = "✓" if ndpr.get('lawful_basis', False) else "✗"
            st.markdown(f"**Lawful Basis:** {status} Clear lawful basis for processing")
            status = "✓" if ndpr.get('consent_management', False) else "✗"
            st.markdown(f"**Consent Management:** {status} Systems for managing consent")
    
    with tab4:
        st.markdown("### Technical Details")
        gdpr = results.get('gdpr', {})
        
        # Security Headers
        with st.expander("Security Headers"):
            headers = gdpr.get('security_headers', {})
            if headers:
                for header, status in headers.items():
                    check_mark = "\u2713"  # ✓
                    x_mark = "\u2717"      # ✗
                    st.markdown(f"- {check_mark if status['present'] else x_mark} {header}: {status.get('value', 'Not found')}")
            else:
                st.markdown("No security headers information available.")
        
        # Cookies Analysis
        with st.expander("Cookies Analysis"):
            cookies = gdpr.get('cookies', {})
            if 'cookies' in cookies and cookies['cookies']:
                st.markdown(f"Found {len(cookies['cookies'])} cookies:")
                for cookie in cookies['cookies']:
                    secure = "✓" if cookie.get('secure', False) else "✗"
                    http_only = "✓" if cookie.get('httpOnly', False) else "✗"
                    st.markdown(f"- {cookie['name']} (Secure: {secure}, HttpOnly: {http_only})")
            else:
                st.markdown("No cookies found or could not be analyzed.")
        
        # CSP Analysis
        with st.expander("Content Security Policy"):
            csp = gdpr.get('csp_analysis', {})
            if csp.get('present', False):
                st.markdown("✓ Content Security Policy is implemented.")
                if csp.get('score', 0) < 100:
                    st.markdown(f"⚠️ CSP could be improved. Score: {csp.get('score', 0)}/100")
                    if csp.get('issues'):
                        st.markdown("**Issues found:**")
                        for issue in csp['issues']:
                            st.markdown(f"- {issue}")
            else:
                st.markdown("✗ No Content Security Policy header found.")
    
    # Add a section for solutions at the end of the page
    st.markdown("---")
    st.markdown("## Implementation Solutions")
    st.markdown("Select an issue to view implementation guidance:")
    
    issue_type = st.selectbox(
        "Select an issue to view solution:",
        ["", "https", "cookie_banner", "privacy_policy"],
        format_func=lambda x: {
            "": "-- Select an issue --",
            "https": "HTTPS & SSL Configuration",
            "cookie_banner": "Cookie Consent Banner",
            "privacy_policy": "Privacy Policy Implementation"
        }[x]
    )
    
    if issue_type:
        show_javascript_solution(issue_type)
    
    # Calculate and display compliance score if available
    if 'score' in locals():
        st.metric("Compliance Score", f"{score:.1f}%")
        st.progress(int(score) / 100)
    
    # Detailed results with tabs
    tab1, tab2, tab3 = st.tabs(["Basic Checks", "Advanced Analysis", "Recommendations"])
    
    with tab1:
        st.markdown('<h2 class="section-title">Basic GDPR Compliance Checks</h2>', unsafe_allow_html=True)
        
        # HTTPS Check
        with st.expander("🔒 HTTPS & SSL", expanded=True):
            passed, message = results.get('https', (False, "Check failed"))
            status_class = "passed" if passed else "failed"
            status_text = "PASSED" if passed else "FAILED"
            status_icon = "✅" if passed else "❌"
            
            st.markdown(f"""
            <div class='check-card'>
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <strong>Status:</strong> <span class='{status_class}'>{status_icon} {status_text}</span>
                    </div>
                </div>
                <div style="margin-top: 0.5rem;">{message}</div>
            </div>
            """, unsafe_allow_html=True)
            
            if not passed:
                with st.container():
                    st.markdown(f"""
                    <div class="warning">
                        <strong>⚠️ Issue:</strong> {GDPR_CHECKS['HTTPS_Enabled']['recommendation']}
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Show JavaScript solution
                    show_javascript_solution("https")
        
        # Cookie Banner Check
        with st.expander("🍪 Cookie Consent Banner", expanded=True):
            passed, message = results.get('cookie_banner', (False, "Check failed"))
            status = "<span class='passed'>✅ Passed</span>" if passed else "<span class='failed'>❌ Failed</span>"
            st.markdown(f"<div class='check-card'><strong>Status:</strong> {status}<br>{message}</div>", unsafe_allow_html=True)
            if not passed:
                st.warning(GDPR_CHECKS['Cookie_Consent_Banner']['recommendation'])
        
        # Privacy Policy Check
        with st.expander("📄 Privacy Policy", expanded=True):
            passed, message = results.get('privacy_policy', (False, "Check failed"))
            status = "<span class='passed'>✅ Passed</span>" if passed else "<span class='failed'>❌ Failed</span>"
            st.markdown(f"<div class='check-card'><strong>Status:</strong> {status}<br>{message}</div>", unsafe_allow_html=True)
            if not passed:
                st.warning(GDPR_CHECKS['Privacy_Policy_Link']['recommendation'])
    
    with tab2:
        st.markdown('<h2 class="section-title">Advanced Security Analysis</h2>', unsafe_allow_html=True)
        
        # Security Headers
        with st.expander("🛡️ Security Headers", expanded=True):
            headers = results.get('security_headers', {})
            if not headers:
                st.error("Failed to check security headers")
            else:
                headers_df = pd.DataFrame([
                    {
                        'Header': header,
                        'Status': '✅ Present' if data['present'] else '❌ Missing',
                        'Value': data['value'] or 'Not set',
                        'Recommendation': data['recommendation']
                    }
                    for header, data in headers.items()
                ])
                st.dataframe(
                    headers_df, 
                    hide_index=True,
                    column_config={
                        "Header": "Header",
                        "Status": "Status",
                        "Value": "Value",
                        "Recommendation": "Recommendation"
                    },
                    use_container_width=True
                )
        
        # CSP Analysis
        with st.expander("🔐 Content Security Policy (CSP)", expanded=True):
            csp = results.get('csp_analysis', {})
            if not csp or not csp.get('present'):
                st.error("No Content Security Policy (CSP) header found")
                st.warning("A strong CSP helps prevent XSS attacks and other code injection attacks.")
            else:
                st.metric("CSP Score", f"{csp.get('score', 0)}%")
                
                if csp.get('issues'):
                    st.warning("CSP Issues Found:")
                    for issue in csp['issues']:
                        st.write(f"- {issue}")
                
                st.subheader("CSP Directives")
                for directive, values in csp.get('directives', {}).items():
                    st.code(f"{directive} {' '.join(values)}", language="http")
        
        # Third-party Trackers
        with st.expander("👥 Third-party Trackers", expanded=True):
            trackers = results.get('third_party_trackers', {})
            if not trackers:
                st.success("No common third-party trackers detected!")
            else:
                st.warning(f"Found {sum(len(v) for v in trackers.values())} potential tracking elements")
                
                # Create tabs for each tracker category instead of nested expanders
                if any(trackers.values()):
                    tracker_tabs = st.tabs([f"{cat.replace('_', ' ').title()} ({len(items)})" 
                                          for cat, items in trackers.items() if items])
                    
                    for tab, (category, items) in zip(tracker_tabs, [(k, v) for k, v in trackers.items() if v]):
                        with tab:
                            for item in items:
                                st.code(item, language="text")
        
        # Privacy Policy Content Analysis
        if 'privacy_policy_content' in results:
            with st.expander("📋 Privacy Policy Analysis", expanded=True):
                content = results['privacy_policy_content']
                if not content:
                    st.warning("Could not analyze privacy policy content")
                else:
                    st.subheader("Key GDPR Sections Found")
                    
                    # Create a grid of checkboxes
                    cols = st.columns(2)
                    for i, (section, found) in enumerate(content.items()):
                        col = cols[i % 2]
                        with col:
                            st.checkbox(
                                label=section.replace('_', ' ').title(),
                                value=found,
                                disabled=True,
                                key=f"privacy_{section}"
                            )
    
    with tab3:
        st.markdown('<h2 class="section-title">Recommendations</h2>', unsafe_allow_html=True)
        
        # Generate recommendations based on findings
        recommendations = []
        
        # HTTPS recommendations
        if not results.get('https', (False,))[0]:
            recommendations.append({
                "priority": "High",
                "issue": "HTTPS Not Properly Configured",
                "recommendation": GDPR_CHECKS['HTTPS_Enabled']['recommendation']
            })
        
        # Cookie banner recommendations
        if not results.get('cookie_banner', (False,))[0]:
            recommendations.append({
                "priority": "High",
                "issue": "Missing Cookie Consent Banner",
                "recommendation": GDPR_CHECKS['Cookie_Consent_Banner']['recommendation']
            })
        
        # Privacy policy recommendations
        if not results.get('privacy_policy', (False,))[0]:
            recommendations.append({
                "priority": "High",
                "issue": "Missing Privacy Policy",
                "recommendation": GDPR_CHECKS['Privacy_Policy_Link']['recommendation']
            })
        
        # Security headers recommendations
        if results.get('security_headers'):
            missing_headers = [h for h, d in results['security_headers'].items() if not d['present']]
            if missing_headers:
                recommendations.append({
                    "priority": "Medium",
                    "issue": f"Missing Security Headers ({len(missing_headers)})",
                    "recommendation": f"Add the following security headers: {', '.join(missing_headers)}. These headers help protect against various web vulnerabilities."
                })
        
        # CSP recommendations
        csp = results.get('csp_analysis', {})
        if not csp or not csp.get('present'):
            recommendations.append({
                "priority": "High",
                "issue": "Missing Content Security Policy (CSP)",
                "recommendation": "Implement a strong Content Security Policy to prevent XSS and other code injection attacks."
            })
        elif csp.get('score', 0) < 80:  # If CSP score is less than 80%
            recommendations.append({
                "priority": "Medium",
                "issue": "Weak Content Security Policy",
                "recommendation": "Strengthen your CSP by fixing the issues identified in the CSP analysis section."
            })
        
        # Third-party trackers recommendations
        trackers = results.get('third_party_trackers', {})
        if trackers and any(trackers.values()):
            tracker_count = sum(len(v) for v in trackers.values())
            recommendations.append({
                "priority": "Medium",
                "issue": f"Third-party Trackers Detected ({tracker_count})",
                "recommendation": "Review all third-party trackers and ensure they are GDPR compliant. Consider using a cookie consent management platform to manage user consent."
            })
        
        # Display recommendations
        if not recommendations:
            st.success("🎉 Great job! No critical issues found. Your website appears to be in good shape regarding GDPR compliance.")
        else:
            # Sort by priority (High, Medium, Low)
            priority_order = {"High": 0, "Medium": 1, "Low": 2}
            recommendations.sort(key=lambda x: priority_order[x["priority"]])
            
            # Group by priority
            for priority in ["High", "Medium", "Low"]:
                prio_recommendations = [r for r in recommendations if r["priority"] == priority]
                if prio_recommendations:
                    st.subheader(f"{priority} Priority")
                    for rec in prio_recommendations:
                        with st.expander(f"{rec['issue']}", expanded=priority=="High"):
                            st.write(rec["recommendation"])
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #6B7280; font-size: 0.9rem; margin-top: 2rem;'>
        <p>This report was generated by Healthcare Compliance Auditor</p>
        <p>Note: This is an automated assessment and may not cover all aspects of healthcare compliance. Consult with a legal expert for a comprehensive compliance review.</p>
    </div>
    """, unsafe_allow_html=True)

def main():
    # Show sidebar
    show_sidebar()
    
    # Main content
    st.markdown("""
    <div style='background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%); padding: 2rem; border-radius: 10px; margin-bottom: 2rem;'>
        <h1 style='color: #0369a1; margin-bottom: 0.5rem;'>Healthcare Compliance Auditor</h1>
        <p style='color: #1e40af; font-size: 1.1rem;'>Ensure your healthcare portal meets regulatory requirements including HIPAA, GDPR, and NDPR</p>
    </div>
    """, unsafe_allow_html=True)
    
    # URL input section
    col1, col2 = st.columns([3, 1])
    with col1:
        url = st.text_input("Enter healthcare portal URL:", "", placeholder="https://your-healthcare-portal.com")
    with col2:
        st.write("")
        st.write("")
        run_button = st.button("🔍 Run Compliance Check", use_container_width=True, type="primary")
    
    # Run compliance check
    if run_button:
        if not url:
            st.error("Please enter a valid healthcare portal URL")
            return
            
        with st.spinner("Scanning for compliance issues..."):
            try:
                results = run_gdpr_audit(url)
                display_results(results, url)
            except Exception as e:
                st.error(f"An error occurred during the scan: {str(e)}")
    
    # Show quick start guide if no URL is entered
    elif not url:
        st.markdown("### 🚀 Getting Started")
        st.write("1. Enter your healthcare portal URL above")
        st.write("2. Click 'Run Compliance Check' to begin scanning")
        st.write("3. Review the detailed compliance report")

# Set page config at the very beginning of the script - this must be the first Streamlit command
st.set_page_config(
    page_title="Healthcare Compliance Auditor",
    page_icon="🏥",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Dark mode CSS
st.markdown("""
<style>
    /* Base dark theme */
    .stApp {
        background-color: #121212;
        color: #e0e0e0;
    }
    
    /* Main content */
    .main .block-container {
        background-color: #121212;
        color: #e0e0e0;
    }
    
    /* Headers */
    h1, h2, h3, h4, h5, h6 {
        color: #bb86fc !important;
    }
    
    /* Text */
    p, div, span {
        color: #e0e0e0 !important;
    }
    
    /* Input fields */
    .stTextInput>div>div>input {
        background-color: #1e1e1e !important;
        color: #e0e0e0 !important;
        border: 1px solid #333;
    }
    
    /* Buttons */
    .stButton>button {
        background-color: #bb86fc !important;
        color: #000000 !important;
        border: none;
        border-radius: 4px;
        padding: 0.5rem 1.5rem;
    }
    
    .stButton>button:hover {
        background-color: #9a67ea !important;
    }
    
    /* Sidebar */
    .css-1d391kg, .css-1d391kg>div {
        background-color: #1e1e1e !important;
    }
    
    /* Expanders */
    .stExpander {
        background-color: #1e1e1e;
        border: 1px solid #333;
    }
    
    /* Cards */
    .stAlert, .stInfo, .stSuccess, .stWarning, .stError {
        background-color: #1e1e1e !important;
        border-left: 4px solid #bb86fc;
    }
    
    /* Tables */
    table {
        color: #e0e0e0 !important;
    }
    
    th, td {
        background-color: #1e1e1e !important;
        border: 1px solid #333 !important;
    }
    
    /* Scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
    }
    
    ::-webkit-scrollbar-track {
        background: #1e1e1e;
    }
    
    ::-webkit-scrollbar-thumb {
        background: #bb86fc;
        border-radius: 4px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: #9a67ea;
    }
    
    /* Section titles */
    .section-title { 
        font-size: 1.5rem !important; 
        font-weight: 600; 
        margin-top: 1.5rem; 
        color: #bb86fc !important; 
        border-bottom: 2px solid #333;
        padding-bottom: 0.5rem;
    }
    
    /* Check cards */
    .check-card { 
        border-left: 4px solid #bb86fc;
        padding: 1rem; 
        margin: 0.5rem 0; 
        border-radius: 4px;
        background-color: #1e1e1e;
        background-color: #F8FAFC;
        transition: all 0.3s ease;
    }
    .check-card:hover {
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    }
    .passed { 
        color: #10B981; 
        font-weight: 600;
        background-color: #ECFDF5;
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        display: inline-block;
        font-size: 0.875rem;
    }
    .failed { 
        color: #EF4444; 
        font-weight: 600;
        background-color: #FEF2F2;
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        display: inline-block;
        font-size: 0.875rem;
    }
    .warning { 
        color: #F59E0B;
        background-color: #FFFBEB;
        padding: 0.5rem 1rem;
        border-radius: 0.375rem;
        margin: 0.5rem 0;
        border-right: 4px solid #F59E0B;
    }
    .info-box { 
        background-color: #EFF6FF; 
        padding: 1rem; 
        border-radius: 0.5rem;
        margin: 0.5rem 0;
        border-left: 4px solid #3B82F6;
    }
    .solution-box {
        background-color: #F0FDF4;
        border-left: 4px solid #10B981;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .solution-title {
        color: #065F46;
        font-weight: 600;
        margin-bottom: 0.5rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 40px;
        padding: 0 16px;
        margin-right: 8px;
        border-radius: 4px;
        font-weight: 500;
    }
    .stTabs [aria-selected="true"] {
        background-color: #3B82F6;
        color: white !important;
    }
    .stTabs [aria-selected="false"] {
        color: #6B7280 !important;
    }
</style>
""", unsafe_allow_html=True)

def show_sidebar():
    # Sidebar styling
    st.markdown("""
    <style>
        /* Sidebar styling */
        [data-testid="stSidebar"] {
            background-color: #1e1e1e;
            color: #e0e0e0;
        }
        
        [data-testid="stSidebar"] .st-af {
            color: #e0e0e0 !important;
        }
        
        [data-testid="stSidebar"] .st-bb {
            color: #e0e0e0 !important;
        }
        
        [data-testid="stSidebar"] .st-bc {
            color: #e0e0e0 !important;
        }
        
        [data-testid="stSidebar"] .st-bd {
            color: #e0e0e0 !important;
        }
    </style>
    """, unsafe_allow_html=True)
    
    st.sidebar.title("🏥 Healthcare Compliance")
    st.sidebar.write("---")
    
    st.sidebar.markdown("### About")
    st.sidebar.markdown("""
    This tool helps healthcare organizations ensure compliance with key regulations 
    including HIPAA, GDPR, and NDPR for protecting patient health information (PHI).
    """)
    
    st.sidebar.write("---")
    st.sidebar.markdown("### Key Regulations")
    with st.sidebar.expander("HIPAA"):
        st.markdown("""
        - **Privacy Rule**
        - **Security Rule**
        - **Breach Notification**
        - **Omnibus Rule**
        """)
    
    with st.sidebar.expander("GDPR"):
        st.write("""
        - Lawful Processing
        - Data Subject Rights
        - DPO Requirements
        - Cross-border Transfers
        """)
    
    with st.sidebar.expander("NDPR"):
        st.write("""
        - Data Protection
        - Consent Management
        - Breach Notification
        - Accountability
        """)
    
    st.sidebar.write("---")
    st.sidebar.markdown("""
    <div style='font-size: 0.8rem; color: #6c757d;'>
        <p>⚠️ This tool provides guidance only and does not constitute legal advice.</p>
        <p>Last updated: {}</p>
    </div>
    """.format(datetime.now().strftime("%Y-%m-%d")), unsafe_allow_html=True)

def show_javascript_solution(issue_type: str):
    """Display JavaScript solution for a specific GDPR requirement"""
    solutions = {
        # HTTPS & SSL Configuration
        "https": {
            "title": "HTTPS & SSL Configuration",
            "description": "Ensure all traffic is encrypted using HTTPS with a valid SSL certificate.",
            "solution": """
            // Redirect HTTP to HTTPS
            if (window.location.protocol === 'http:') {
                window.location.href = 'https:' + window.location.href.substring(5);
            }
            
            // Check SSL certificate
            document.addEventListener('DOMContentLoaded', function() {
                // This would need to be implemented server-side for actual validation
                console.log('SSL Certificate should be valid and not expired');
            });
            """,
            "server_side": """
            # Apache (.htaccess)
            RewriteEngine On
            RewriteCond %{HTTPS} off
            RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
            
            # Nginx
            server {
                listen 80;
                server_name yourdomain.com;
                return 301 https://$server_name$request_uri;
            }
            """
        },
        
        # Cookie Consent Banner with Dark Mode
        "cookie_banner": {
            "title": "Cookie Consent Banner with Dark Mode",
            "description": "A GDPR-compliant cookie consent banner with dark mode support and privacy policy integration.",
            "solution": """
            // Cookie Consent Banner with Dark Mode
            document.addEventListener('DOMContentLoaded', function() {
                const COOKIE_NAME = 'gdpr_consent';
                const DARK_MODE_COOKIE = 'dark_mode';
                
                // Check if dark mode is enabled
                const isDarkMode = getCookie(DARK_MODE_COOKIE) === 'true' || 
                                 (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
                
                // Apply dark mode
                if (isDarkMode) {
                    document.documentElement.setAttribute('data-theme', 'dark');
                }
                
                // Toggle dark mode function
                window.toggleDarkMode = function() {
                    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
                    document.documentElement.setAttribute('data-theme', isDark ? 'light' : 'dark');
                    setCookie(DARK_MODE_COOKIE, (!isDark).toString(), 365);
                };
                
                // Only show banner if consent not given
                if (!getCookie(COOKIE_NAME)) {
                    const banner = document.createElement('div');
                    banner.id = 'gdpr-banner';
                    banner.style.cssText = `
                        position: fixed;
                        bottom: 0;
                        left: 0;
                        right: 0;
                        background: var(--bg-color, #1e1e1e);
                        color: var(--text-color, #e0e0e0);
                        padding: 1.5rem;
                        box-shadow: 0 -2px 10px rgba(0,0,0,0.3);
                        z-index: 1000;
                        font-family: Arial, sans-serif;
                        border-top: 1px solid var(--border-color, #333);
                        transition: all 0.3s ease;
                    `;
                    
                    banner.innerHTML = `
                        <div style="max-width: 1200px; margin: 0 auto; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 1rem;">
                            <div style="flex: 1; min-width: 200px;">
                                <p style="margin: 0; font-size: 0.9rem; line-height: 1.5; color: var(--text-color, #e0e0e0);">
                                    We use cookies to enhance your experience. By continuing to visit this site, you agree to our use of cookies.
                                    <a href="/privacy-policy" style="color: var(--primary-color, #4a90e2); text-decoration: none;">Privacy Policy</a>
                                </p>
                            </div>
                            <div style="display: flex; gap: 0.75rem; flex-wrap: wrap; align-items: center;">
                                <button onclick="toggleDarkMode()" style="background: transparent; border: 1px solid var(--border-color, #555); border-radius: 50%; width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; cursor: pointer; color: var(--text-color, #e0e0e0);">
                                    <span id="theme-icon">🌙</span>
                                </button>
                                <button onclick="handleCookieConsent('reject')" style="padding: 0.5rem 1.25rem; background: transparent; color: var(--text-color, #e0e0e0); border: 1px solid var(--border-color, #555); border-radius: 4px; cursor: pointer; font-weight: 500; transition: all 0.2s ease;">
                                    Reject All
                                </button>
                                <button onclick="showCookieSettings()" style="padding: 0.5rem 1.25rem; background: transparent; color: var(--primary-color, #4a90e2); border: 1px solid var(--primary-color, #4a90e2); border-radius: 4px; cursor: pointer; font-weight: 500; transition: all 0.2s ease;">
                                    Customize
                                </button>
                                <button onclick="handleCookieConsent('accept')" style="padding: 0.5rem 1.25rem; background: var(--primary-color, #4a90e2); color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; transition: all 0.2s ease;">
                                    Accept All
                                </button>
                            </div>
                        </div>
                        
                        <style>
                            :root {
                                --bg-color: #1e1e1e;
                                --text-color: #e0e0e0;
                                --primary-color: #4a90e2;
                                --secondary-color: #2d2d2d;
                                --border-color: #444;
                                --card-bg: #252525;
                            }
                            
                            [data-theme="light"] {
                                --bg-color: #ffffff;
                                --text-color: #333333;
                                --primary-color: #1a73e8;
                                --secondary-color: #f5f5f5;
                                --border-color: #e0e0e0;
                                --card-bg: #ffffff;
                            }
                            
                            body {
                                background-color: var(--bg-color);
                                color: var(--text-color);
                                transition: background-color 0.3s ease, color 0.3s ease;
                            }
                            
                            button {
                                transition: all 0.2s ease;
                            }
                            
                            button:hover {
                                opacity: 0.9;
                                transform: translateY(-1px);
                            }
                            
                            #theme-icon {
                                transition: transform 0.3s ease;
                            }
                            
                            [data-theme="dark"] #theme-icon {
                                transform: rotate(180deg);
                            }
                        </style>
                        
                        <script>
                        // Handle cookie consent
                        window.handleCookieConsent = function(action) {
                            if (action === 'accept') {
                                // Set consent cookie for 1 year
                                document.cookie = 'cookie_consent=true; max-age=31536000; path=/; SameSite=Lax; Secure';
                                // Enable all cookies
                                enableAllCookies();
                            } else {
                                // Set rejection cookie for 1 year
                                document.cookie = 'cookie_consent=false; max-age=31536000; path=/; SameSite=Lax; Secure';
                                // Disable non-essential cookies
                                disableNonEssentialCookies();
                            }
                            // Hide the banner
                            document.getElementById('gdpr-banner').style.display = 'none';
                        };
                        
                        // Show cookie settings modal
                        window.showCookieSettings = function() {
                            alert('Cookie settings would open here');
                            // Implement your cookie settings modal here
                        };
                        
                        // Enable all cookies
                        function enableAllCookies() {
                            // Load analytics, tracking, etc.
                            console.log('All cookies enabled');
                        }
                        
                        // Disable non-essential cookies
                        function disableNonEssentialCookies() {
                            // Disable analytics, tracking, etc.
                            console.log('Non-essential cookies disabled');
                        }
                        
                        // Cookie helper function
                        function getCookie(name) {
                            const value = `; ${document.cookie}`;
                            const parts = value.split(`; ${name}=`);
                            if (parts.length === 2) return parts.pop().split(';').shift();
                            return null;
                        }
                        </script>
                    `;
                    
                    document.body.appendChild(banner);
                    
                    // Event listeners
                    document.getElementById('accept-all').addEventListener('click', function() {
                        setCookie(COOKIE_NAME, 'all', 365);
                        banner.style.display = 'none';
                        initializeTracking('all');
                    });
                    
                    document.getElementById('customize').addEventListener('click', function() {
                        // Show preferences panel (implementation not shown for brevity)
                        console.log('Show cookie preferences');
                    });
                }
                
                // Helper functions
                function setCookie(name, value, days) {
                    let expires = '';
                    if (days) {
                        const date = new Date();
                        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
                        expires = '; expires=' + date.toUTCString();
                    }
                    document.cookie = name + '=' + (value || '') + expires + '; path=/; SameSite=Lax' + (location.protocol === 'https:' ? '; Secure' : '');
                }
                
                function getCookie(name) {
                    const nameEQ = name + '=';
                    const ca = document.cookie.split(';');
                    for (let i = 0; i < ca.length; i++) {
                        let c = ca[i];
                        while (c.charAt(0) === ' ') c = c.substring(1, c.length);
                        if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
                    }
                    return null;
                }
                
                function initializeTracking(level) {
                    // Initialize tracking based on user's consent level
                    console.log('Initializing tracking at level:', level);
                }
            });
            """,
            "server_side": """
            # Server-side implementation would involve:
            # 1. Storing user preferences in a database
            # 2. Respecting Do Not Track (DNT) headers
            # 3. Implementing API endpoints for preference management
            # 4. Setting appropriate HTTP-only cookies for security
            
            # Example PHP implementation:
            /*
            <?php
            header('Content-Type: application/json');
            
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $data = json_decode(file_get_contents('php://input'), true);
                $preferences = [
                    'analytics' => $data['analytics'] ?? false,
                    'marketing' => $data['marketing'] ?? false,
                    'timestamp' => time()
                ];
                
                // Set cookie (30 days expiration)
                setcookie(
                    'gdpr_consent',
                    json_encode($preferences),
                    time() + (30 * 24 * 60 * 60),
                    '/',
                    $_SERVER['HTTP_HOST'],
                    isset($_SERVER['HTTPS']),
                    true // HttpOnly
                );
                
                echo json_encode(['success' => true]);
                exit;
            }
            ?>
            """
        },
        
        # Privacy Policy
        "privacy_policy": {
            "title": "Privacy Policy",
            "description": "Ensure a clear and accessible privacy policy is available that explains data collection and processing.",
            "solution": """
            // Add a privacy policy link to your navigation
            document.addEventListener('DOMContentLoaded', function() {
                // Try to find existing navigation elements
                const nav = document.querySelector('nav') || 
                            document.querySelector('header') || 
                            document.querySelector('footer') || 
                            document.body;
                
                // Create privacy policy link
                const privacyLink = document.createElement('a');
                privacyLink.href = '/privacy-policy';
                privacyLink.textContent = 'Privacy Policy';
                privacyLink.style.margin = '0 1rem';
                privacyLink.style.color = '#3182ce';
                privacyLink.style.textDecoration = 'none';
                privacyLink.style.fontWeight = '500';
                privacyLink.style.transition = 'color 0.2s';
                privacyLink.style.padding = '0.5rem 0';
                privacyLink.style.display = 'inline-block';
                
                // Add hover effect
                privacyLink.addEventListener('mouseover', () => {
                    privacyLink.style.color = '#2c5282';
                    privacyLink.style.textDecoration = 'underline';
                });
                privacyLink.addEventListener('mouseout', () => {
                    privacyLink.style.color = '#3182ce';
                    privacyLink.style.textDecoration = 'none';
                });
                
                // Add to navigation
                if (nav.tagName === 'NAV' || nav.tagName === 'HEADER' || nav.tagName === 'FOOTER') {
                    // Create a list item if inside a navigation list
                    const list = nav.querySelector('ul, ol') || document.createElement('ul');
                    const listItem = document.createElement('li');
                    listItem.style.display = 'inline-block';
                    listItem.style.margin = '0 0.5rem';
                    listItem.appendChild(privacyLink);
                    
                    if (!nav.contains(list)) {
                        nav.appendChild(list);
                    }
                    list.appendChild(listItem);
                } else {
                    // Add directly to the body in a footer-like container
                    let footer = document.querySelector('footer');
                    if (!footer) {
                        footer = document.createElement('footer');
                        footer.style.padding = '2rem 1rem';
                        footer.style.backgroundColor = '#f7fafc';
                        footer.style.borderTop = '1px solid #e2e8f0';
                        footer.style.marginTop = '3rem';
                        footer.style.textAlign = 'center';
                        document.body.appendChild(footer);
                    }
                    
                    const container = document.createElement('div');
                    container.style.maxWidth = '1200px';
                    container.style.margin = '0 auto';
                    container.style.padding = '0 1rem';
                    container.style.textAlign = 'center';
                    container.style.fontSize = '0.9em';
                    container.style.color = '#4a5568';
                    
                    // Add other legal links
                    const links = [
                        { text: 'Privacy Policy', href: '/privacy-policy' },
                        { text: 'Cookie Policy', href: '/cookie-policy' },
                        { text: 'Terms of Service', href: '/terms' },
                        { text: 'Contact Us', href: '/contact' }
                    ];
                    
                    const linksContainer = document.createElement('div');
                    linksContainer.style.marginBottom = '1rem';
                    
                    links.forEach((link, index) => {
                        if (index > 0) {
                            const separator = document.createTextNode(' • ');
                            linksContainer.appendChild(separator);
                        }
                        
                        const a = document.createElement('a');
                        a.href = link.href;
                        a.textContent = link.text;
                        a.style.color = '#3182ce';
                        a.style.textDecoration = 'none';
                        a.style.padding = '0.25rem 0.5rem';
                        a.style.borderRadius = '0.25rem';
                        a.style.transition = 'all 0.2s';
                        
                        a.addEventListener('mouseover', () => {
                            a.style.backgroundColor = '#ebf8ff';
                            a.style.textDecoration = 'underline';
                        });
                        a.addEventListener('mouseout', () => {
                            a.style.backgroundColor = 'transparent';
                            a.style.textDecoration = 'none';
                        });
                        
                        linksContainer.appendChild(a);
                    });
                    
                    container.appendChild(linksContainer);
                    container.appendChild(document.createTextNode(`© ${new Date().getFullYear()} Your Company. All rights reserved.`));
                    footer.appendChild(container);
                }
            });
            """,
            "server_side": """
            # Server-side implementation would involve:
            # 1. Creating a privacy policy page with all required GDPR information
            # 2. Ensuring the page is accessible and properly linked
            # 3. Including all required sections:
            #    - Data controller information
            #    - Types of data collected
            #    - Purpose of data processing
            #    - Legal basis for processing
            #    - Data retention periods
            #    - Data subject rights
            #    - Contact information for DPO
            
            # Example database schema for privacy policy versions:
            """
        }
    }
    
    solution = solutions.get(issue_type, None)
    if solution:
        # Instead of using an expander, create a clean section with a header
        st.markdown("### 🛠️ Implementation Solution")
        st.markdown("#### Client-side (JavaScript)")
        st.code(solution["solution"], language="javascript")
        
        st.markdown("#### Server-side Configuration")
        st.code(solution["server_side"], language="bash")
        
        st.markdown("""
        <div class="info-box" style="margin-top: 1rem; padding: 1rem; background-color: #f8f9fa; border-radius: 0.5rem; border-left: 4px solid #4285f4;">
            <strong>ℹ️ Note:</strong> Some solutions (like security headers) need to be implemented server-side and cannot be handled by client-side JavaScript alone.
        </div>
        """, unsafe_allow_html=True)

def main():
    # Show sidebar
    show_sidebar()
    
    # Main content
    st.title("GDPR Compliance Checker")
    st.markdown("""
    <div class="info-box">
        Enter a website URL below to check its GDPR compliance. The tool will analyze the website for 
        various GDPR requirements including cookie consent, privacy policy, security headers, and more.
    </div>
    """, unsafe_allow_html=True)
    
    # URL input with better styling
    col1, col2 = st.columns([3, 1])
    with col1:
        url = st.text_input("Enter website URL (e.g., https://example.com):", "", 
                           placeholder="https://example.com")
    with col2:
        st.write("")
        run_check = st.button("Run GDPR Check", use_container_width=True, 
                             type="primary", help="Click to start the GDPR compliance check")
    
    # Add some spacing
    st.markdown("<br>", unsafe_allow_html=True)
    
    if run_check and url:
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        
        with st.spinner("Running GDPR compliance checks..."):
            results = run_gdpr_audit(url)
            display_results(results, url)

if __name__ == "__main__":
    # Clear any existing session state if needed
    if 'results' in st.session_state:
        del st.session_state['results']
    main()
