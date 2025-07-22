#!/usr/bin/env python3
"""
Laravel Environment Variable Manipulation Vulnerability Scanner (CVE-2024-52301)

This module detects Laravel's environment variable manipulation vulnerability
by testing session configuration manipulation through URL parameters and
analyzing response behavior for indicators of successful exploitation.
"""

import requests
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Optional, Union, Set


def scan(target_url: str) -> Optional[Dict[str, Union[str, int]]]:
    """
    Scan for Laravel environment variable manipulation vulnerability (CVE-2024-52301).
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Dictionary with vulnerability details if found, None otherwise
        Format: {"path": "/?LARAVEL_SESSION[driver]=database", "status": "potentially vulnerable", "http_status": 200}
    """
    if not target_url:
        return None
    
    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    # Remove trailing slash and existing query parameters for clean testing
    base_url = target_url.split('?')[0].rstrip('/')
    
    # Test payload for CVE-2024-52301
    test_params = "?LARAVEL_SESSION[driver]=database&LARAVEL_SESSION[connection]=sqlite"
    test_url = base_url + test_params
    
    try:
        # Get baseline response first (without manipulation)
        baseline_response = _get_baseline_response(base_url)
        
        # Send request with session manipulation payload
        response = requests.get(
            test_url,
            timeout=10,
            allow_redirects=True
        )
        
        # Check if response indicates vulnerability
        if _is_vulnerable_response(response, baseline_response):
            return {
                "path": test_params,
                "status": "potentially vulnerable",
                "http_status": response.status_code,
                "url": test_url
            }
            
    except Exception:
        # Silently handle any network or parsing errors
        pass
    
    return None


def _get_baseline_response(base_url: str) -> Optional[requests.Response]:
    """
    Get baseline response without manipulation for comparison.
    
    Args:
        base_url (str): The base URL without parameters
        
    Returns:
        Optional[requests.Response]: Baseline response or None if failed
    """
    try:
        return requests.get(base_url, timeout=10, allow_redirects=True)
    except Exception:
        return None


def _is_vulnerable_response(response: requests.Response, baseline: Optional[requests.Response]) -> bool:
    """
    Analyze response to determine if it indicates vulnerability.
    
    Args:
        response: The HTTP response with manipulation payload
        baseline: The baseline response without manipulation
        
    Returns:
        bool: True if response indicates potential vulnerability
    """
    # Must have successful status code
    if response.status_code != 200:
        return False
    
    try:
        content = response.text.lower()
        
        # Check for suspicious session-related content changes
        session_indicators = [
            'sqlite',
            'database session',
            'session driver',
            'session connection',
            'laravel_session',
            'database/sessions',
            'sqlite3'
        ]
        
        # Check if any session manipulation indicators are present
        content_match = any(indicator in content for indicator in session_indicators)
        
        # Check for new or modified cookies
        cookie_changes = _check_cookie_changes(response, baseline)
        
        # Check for response header changes
        header_changes = _check_header_changes(response, baseline)
        
        # Check for content length changes (potential session behavior modification)
        content_changes = _check_content_changes(response, baseline)
        
        # Vulnerability detected if multiple indicators present
        indicators_count = sum([
            content_match,
            cookie_changes,
            header_changes,
            content_changes
        ])
        
        return indicators_count >= 1  # At least one indicator should be present
        
    except Exception:
        return False


def _check_cookie_changes(response: requests.Response, baseline: Optional[requests.Response]) -> bool:
    """
    Check for new or modified cookies indicating session manipulation.
    
    Args:
        response: Response with manipulation payload
        baseline: Baseline response without manipulation
        
    Returns:
        bool: True if significant cookie changes detected
    """
    try:
        current_cookies = set(response.cookies.keys())
        
        # Check for Laravel session cookies
        laravel_cookies = {
            'laravel_session',
            'XSRF-TOKEN',
            'remember_web'
        }
        
        # If Laravel session cookies are present, it's suspicious
        if any(cookie in current_cookies for cookie in laravel_cookies):
            return True
        
        # Compare with baseline if available
        if baseline:
            baseline_cookies = set(baseline.cookies.keys())
            
            # Check for new cookies
            new_cookies = current_cookies - baseline_cookies
            if new_cookies:
                return True
            
            # Check for modified cookie values
            for cookie_name in current_cookies.intersection(baseline_cookies):
                if response.cookies.get(cookie_name) != baseline.cookies.get(cookie_name):
                    return True
                    
    except Exception:
        pass
    
    return False


def _check_header_changes(response: requests.Response, baseline: Optional[requests.Response]) -> bool:
    """
    Check for response header changes indicating session manipulation.
    
    Args:
        response: Response with manipulation payload
        baseline: Baseline response without manipulation
        
    Returns:
        bool: True if significant header changes detected
    """
    try:
        # Check for session-related headers
        session_headers = [
            'set-cookie',
            'x-session-driver',
            'x-laravel-session'
        ]
        
        current_headers = {k.lower(): v for k, v in response.headers.items()}
        
        # Check for suspicious headers
        if any(header in current_headers for header in session_headers):
            if baseline:
                baseline_headers = {k.lower(): v for k, v in baseline.headers.items()}
                
                # Compare header values
                for header in session_headers:
                    if (header in current_headers and 
                        (header not in baseline_headers or 
                         current_headers[header] != baseline_headers.get(header))):
                        return True
            else:
                return True
                
    except Exception:
        pass
    
    return False


def _check_content_changes(response: requests.Response, baseline: Optional[requests.Response]) -> bool:
    """
    Check for content changes indicating session behavior modification.
    
    Args:
        response: Response with manipulation payload
        baseline: Baseline response without manipulation
        
    Returns:
        bool: True if significant content changes detected
    """
    try:
        if not baseline:
            return False
        
        current_length = len(response.content)
        baseline_length = len(baseline.content)
        
        # Check for significant content length changes (more than 5% difference)
        if baseline_length > 0:
            length_diff = abs(current_length - baseline_length) / baseline_length
            if length_diff > 0.05:  # 5% threshold
                return True
        
        # Check for new error messages or session-related content
        current_content = response.text.lower()
        baseline_content = baseline.text.lower()
        
        session_error_patterns = [
            'session configuration',
            'database session',
            'sqlite session',
            'session driver error',
            'laravel session'
        ]
        
        for pattern in session_error_patterns:
            if pattern in current_content and pattern not in baseline_content:
                return True
                
    except Exception:
        pass
    
    return False


def scan_detailed(target_url: str) -> Optional[Dict[str, Union[str, int, Dict, List]]]:
    """
    Perform detailed scan with comprehensive response analysis.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Detailed vulnerability information
    """
    if not target_url:
        return None
    
    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    base_url = target_url.split('?')[0].rstrip('/')
    test_params = "?LARAVEL_SESSION[driver]=database&LARAVEL_SESSION[connection]=sqlite"
    test_url = base_url + test_params
    
    try:
        baseline_response = _get_baseline_response(base_url)
        response = requests.get(test_url, timeout=10, allow_redirects=True)
        
        if _is_vulnerable_response(response, baseline_response):
            # Extract detailed analysis
            analysis = _detailed_response_analysis(response, baseline_response)
            
            return {
                "path": test_params,
                "status": "potentially vulnerable",
                "http_status": response.status_code,
                "url": test_url,
                "response_size": len(response.content),
                "analysis": analysis,
                "cookies": dict(response.cookies),
                "response_headers": dict(response.headers)
            }
            
    except Exception:
        pass
    
    return None


def _detailed_response_analysis(response: requests.Response, baseline: Optional[requests.Response]) -> Dict[str, Union[bool, List[str]]]:
    """
    Perform detailed analysis of response indicators.
    
    Args:
        response: Response with manipulation payload
        baseline: Baseline response without manipulation
        
    Returns:
        Dict: Detailed analysis results
    """
    analysis = {
        "content_indicators": [],
        "cookie_changes": False,
        "header_changes": False,
        "content_length_change": False
    }
    
    try:
        content = response.text.lower()
        
        # Check for content indicators
        indicators = ['sqlite', 'database session', 'session driver', 'laravel_session']
        analysis["content_indicators"] = [ind for ind in indicators if ind in content]
        
        # Check changes compared to baseline
        if baseline:
            analysis["cookie_changes"] = _check_cookie_changes(response, baseline)
            analysis["header_changes"] = _check_header_changes(response, baseline)
            analysis["content_length_change"] = _check_content_changes(response, baseline)
            
    except Exception:
        pass
    
    return analysis


def test_multiple_payloads(target_url: str) -> Optional[Dict[str, Union[str, int, List]]]:
    """
    Test multiple environment variable manipulation payloads.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Vulnerability information with payload details
    """
    if not target_url:
        return None
    
    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    base_url = target_url.split('?')[0].rstrip('/')
    
    # Alternative payloads to test
    test_payloads = [
        "?LARAVEL_SESSION[driver]=database&LARAVEL_SESSION[connection]=sqlite",
        "?LARAVEL_SESSION[driver]=file&LARAVEL_SESSION[path]=/tmp",
        "?LARAVEL_SESSION[driver]=redis&LARAVEL_SESSION[connection]=default",
        "?APP_ENV=local&APP_DEBUG=true"
    ]
    
    baseline_response = _get_baseline_response(base_url)
    
    for payload in test_payloads:
        try:
            test_url = base_url + payload
            response = requests.get(test_url, timeout=10, allow_redirects=True)
            
            if _is_vulnerable_response(response, baseline_response):
                return {
                    "path": payload,
                    "status": "potentially vulnerable",
                    "http_status": response.status_code,
                    "url": test_url,
                    "successful_payload": payload
                }
                
        except Exception:
            continue
    
    return None


def batch_scan(urls: List[str]) -> List[Dict[str, Union[str, Dict, None]]]:
    """
    Scan multiple URLs for CVE-2024-52301 vulnerability.
    
    Args:
        urls (List[str]): List of URLs to scan
        
    Returns:
        List[Dict]: List of scan results for each URL
    """
    results = []
    
    for url in urls:
        scan_result = scan(url)
        results.append({
            "url": url,
            "result": scan_result
        })
    
    return results