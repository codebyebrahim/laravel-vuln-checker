"""
mass_assignment_checker.py

A security testing module for detecting Mass Assignment vulnerabilities in Laravel applications.
This tool is intended for authorized security testing only.
"""

import requests
import json
from typing import Dict, Optional, List, Tuple
from urllib.parse import urljoin
from collections import Counter
import sys

# ANSI color codes for terminal output
class Colors:
    CRITICAL = '\033[91m'    # Red
    WARNING = '\033[93m'     # Yellow
    SUCCESS = '\033[92m'     # Green
    INFO = '\033[94m'        # Blue
    BOLD = '\033[1m'
    RESET = '\033[0m'
    
    @staticmethod
    def disable():
        """Disable colors if terminal doesn't support them"""
        Colors.CRITICAL = ''
        Colors.WARNING = ''
        Colors.SUCCESS = ''
        Colors.INFO = ''
        Colors.BOLD = ''
        Colors.RESET = ''

# Check if colors are supported
if not sys.stdout.isatty():
    Colors.disable()

# Common Laravel endpoints that might be vulnerable
COMMON_ENDPOINTS = [
    '/register',
    '/api/register',
    '/api/user',
    '/api/users',
    '/api/profile',
    '/api/settings',
    '/api/account',
    '/users',
    '/user/update',
    '/profile/update',
    '/account/update',
    '/api/me',
    '/api/update-profile',
    '/api/user/update'
]

# Suspicious parameters with their risk scores (1-10)
SUSPICIOUS_PARAMS = {
    'is_admin': (True, 10),
    'admin': (True, 9),
    'role': ('admin', 9),
    'is_superuser': (True, 10),
    'superuser': (True, 9),
    'access_level': (999, 8),
    'permission': ('admin', 8),
    'user_type': ('admin', 8),
    'is_moderator': (True, 7),
    'is_staff': (True, 7),
    'privileges': (['admin', 'superuser'], 8),
    'role_id': (1, 7),
    'group': ('administrators', 8),
    'verified': (True, 5),
    'email_verified': (True, 5),
    'approved': (True, 6),
    'active': (True, 5),
    'premium': (True, 4),
    'subscription_level': ('premium', 4),
    'credits': (999999, 3),
    'balance': (999999, 3)
}

def calculate_vulnerability_score(payload: Dict) -> int:
    """
    Calculate vulnerability score based on the parameters in the payload.
    
    Args:
        payload: The payload dictionary
        
    Returns:
        Score from 1-10
    """
    max_score = 0
    for param in payload:
        if param in SUSPICIOUS_PARAMS:
            _, score = SUSPICIOUS_PARAMS[param]
            max_score = max(max_score, score)
    return max_score

def print_vulnerable_result(result: Dict):
    """Print a vulnerability result with color formatting"""
    score = result['vulnerability_score']
    
    # Determine severity level
    if score >= 8:
        severity = f"{Colors.CRITICAL}[CRITICAL]{Colors.RESET}"
    elif score >= 6:
        severity = f"{Colors.WARNING}[HIGH]{Colors.RESET}"
    elif score >= 4:
        severity = f"{Colors.WARNING}[MEDIUM]{Colors.RESET}"
    else:
        severity = f"{Colors.INFO}[LOW]{Colors.RESET}"
    
    print(f"\n{severity} Mass Assignment Possible on {Colors.BOLD}{result['endpoint']}{Colors.RESET} [{result['method']}]")
    
    # Print vulnerable parameters
    for param in result['payload']:
        if param in SUSPICIOUS_PARAMS:
            print(f"  {Colors.WARNING}Parameter:{Colors.RESET} {param}")
    
    print(f"  Response Code: {result['status_code']}")
    print(f"  Snippet: {result['response_snippet'][:100]}...")
    print(f"  {Colors.BOLD}Score: {score}/10{Colors.RESET}")

def check_endpoint(base_url: str, endpoint: str, method: str = 'POST', 
                   payload: Dict = None, timeout: int = 3) -> Optional[Dict]:
    """
    Test a single endpoint for mass assignment vulnerability.
    
    Args:
        base_url: The base URL of the target
        endpoint: The endpoint path to test
        method: HTTP method (POST or PUT)
        payload: The payload to send
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary with vulnerability details if found, None otherwise
    """
    url = urljoin(base_url, endpoint)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Security Scanner)'
    }
    
    try:
        if method == 'POST':
            response = requests.post(url, json=payload, headers=headers, 
                                   timeout=timeout, allow_redirects=False)
        else:  # PUT
            response = requests.put(url, json=payload, headers=headers, 
                                  timeout=timeout, allow_redirects=False)
        
        # Check if authentication is required
        if response.status_code in [401, 403]:
            return None
        
        # Check for potential vulnerability indicators
        if response.status_code in [200, 201, 204]:
            # Try to parse response
            try:
                response_data = response.json()
                response_text = json.dumps(response_data)
            except:
                response_text = response.text[:200]
            
            # Check if any suspicious parameters appear in the response
            vulnerable_params = []
            for param, value in payload.items():
                if param in SUSPICIOUS_PARAMS and param in response_text:
                    vulnerable_params.append(param)
            
            # If we found vulnerable params or got a success response with suspicious payload
            if vulnerable_params or (response.status_code in [200, 201] and 
                                   any(p in SUSPICIOUS_PARAMS for p in payload)):
                return {
                    'url': url,
                    'endpoint': endpoint,
                    'method': method,
                    'payload': payload,
                    'status_code': response.status_code,
                    'response_snippet': response_text[:200],
                    'vulnerability_score': calculate_vulnerability_score(payload),
                    'vulnerable_params': vulnerable_params
                }
                
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.ConnectionError:
        pass
    except Exception:
        pass
    
    return None

def scan(target_url: str) -> List[Dict]:
    """
    Scan a Laravel application for mass assignment vulnerabilities.
    
    Args:
        target_url: The base URL of the target application
        
    Returns:
        List of dictionaries with vulnerability details, empty list if none found
    """
    # Normalize target URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    target_url = target_url.rstrip('/')
    
    print(f"{Colors.INFO}Starting mass assignment vulnerability scan on {Colors.BOLD}{target_url}{Colors.RESET}")
    print(f"{Colors.INFO}Testing {len(COMMON_ENDPOINTS)} endpoints...{Colors.RESET}\n")
    
    vulnerabilities = []
    endpoints_tested = 0
    all_vulnerable_params = []
    
    # Test each endpoint with different payloads
    for endpoint in COMMON_ENDPOINTS:
        endpoint_tested = False
        
        # Create test payloads with different combinations
        test_payloads = [
            {'is_admin': True, 'email': 'test@example.com', 'password': 'password123'},
            {'role': 'admin', 'username': 'testuser', 'name': 'Test User'},
            {'access_level': 999, 'is_superuser': True},
            {'user_type': 'admin', 'permission': 'admin'},
            {'is_admin': True, 'role': 'admin', 'is_moderator': True},
            {param: value[0] for param, value in list(SUSPICIOUS_PARAMS.items())[:10]}  # Test subset
        ]
        
        for payload in test_payloads:
            # Test POST method
            result = check_endpoint(target_url, endpoint, 'POST', payload)
            if result:
                vulnerabilities.append(result)
                all_vulnerable_params.extend(result.get('vulnerable_params', []))
                print_vulnerable_result(result)
            
            if not endpoint_tested:
                endpoints_tested += 1
                endpoint_tested = True
                print(f"{Colors.SUCCESS}✓{Colors.RESET} Tested {endpoint}", end='\r')
            
            # Test PUT method for update endpoints
            if any(keyword in endpoint for keyword in ['update', 'profile', 'settings', 'user']):
                result = check_endpoint(target_url, endpoint, 'PUT', payload)
                if result:
                    vulnerabilities.append(result)
                    all_vulnerable_params.extend(result.get('vulnerable_params', []))
                    print_vulnerable_result(result)
    
    # Clear the progress line
    print(" " * 80, end='\r')
    
    # Generate summary
    print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}Summary:{Colors.RESET}")
    print(f"  Endpoints tested: {endpoints_tested}")
    print(f"  Vulnerable combinations: {len(vulnerabilities)}")
    
    if vulnerabilities:
        # Sort vulnerabilities by score
        vulnerabilities.sort(key=lambda x: x['vulnerability_score'], reverse=True)
        
        # Count vulnerable parameters
        param_counter = Counter(all_vulnerable_params)
        top_params = param_counter.most_common(3)
        
        if top_params:
            print(f"  Top risky params: {', '.join([p[0] for p in top_params])}")
        
        print(f"\n{Colors.CRITICAL}⚠  Mass assignment vulnerabilities detected!{Colors.RESET}")
        print(f"{Colors.WARNING}Please review and patch these endpoints immediately.{Colors.RESET}")
    else:
        print(f"\n{Colors.SUCCESS}✓ No mass assignment vulnerabilities detected.{Colors.RESET}")
    
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")
    
    return vulnerabilities

# Example usage
if __name__ == "__main__":
    # Example: results = scan("https://example.com")
    # This will print colored output and return all vulnerabilities found
    pass