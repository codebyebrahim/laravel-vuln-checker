#!/usr/bin/env python3
"""
Laravel Token Leakage Scanner

This module checks for Laravel tokens (XSRF, session) in response headers
and cookies, analyzing their security configurations and potential exposure.
"""

import requests
from typing import Dict, List, Optional, Union


def scan(target_url: str) -> Optional[Dict[str, Union[str, List[Dict]]]]:
    """
    Scan for Laravel token leakage in response headers and cookies.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Dictionary with token information if found, None otherwise
        Format: {"url": "https://example.com", "cookies": [{"name": "XSRF-TOKEN", "httponly": False, "secure": True}]}
    """
    if not target_url:
        return None
    
    try:
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        target_url = target_url.rstrip('/')
        
        # Send request to base URL
        response = requests.get(
            target_url,
            timeout=10,
            allow_redirects=True
        )
        
        # Extract Laravel-specific cookies from response
        laravel_cookies = _extract_laravel_cookies(response)
        
        if laravel_cookies:
            return {
                "url": target_url,
                "cookies": laravel_cookies
            }
        
    except Exception:
        # Silently handle all exceptions
        pass
    
    return None


def _extract_laravel_cookies(response: requests.Response) -> List[Dict[str, Union[str, bool]]]:
    """
    Extract and analyze Laravel-specific cookies from response.
    
    Args:
        response: The HTTP response object
        
    Returns:
        List[Dict]: List of Laravel cookies with their security attributes
    """
    laravel_cookies = []
    
    try:
        # Laravel cookie names to look for
        laravel_cookie_names = [
            'XSRF-TOKEN',
            'laravel_session',
            'debugbar'
        ]
        
        # Check Set-Cookie headers
        set_cookie_headers = response.headers.get_list('Set-Cookie') if hasattr(response.headers, 'get_list') else []
        if not set_cookie_headers and 'Set-Cookie' in response.headers:
            set_cookie_headers = [response.headers['Set-Cookie']]
        
        for cookie_header in set_cookie_headers:
            cookie_info = _parse_cookie_header(cookie_header)
            
            # Check if this is a Laravel cookie
            if cookie_info and cookie_info['name'] in laravel_cookie_names:
                laravel_cookies.append(cookie_info)
        
        # Also check response.cookies object
        for cookie in response.cookies:
            if cookie.name in laravel_cookie_names:
                cookie_info = {
                    'name': cookie.name,
                    'httponly': cookie.has_nonstandard_attr('HttpOnly') or getattr(cookie, 'httponly', False),
                    'secure': cookie.secure,
                    'samesite': getattr(cookie, 'samesite', None),
                    'domain': cookie.domain,
                    'path': cookie.path
                }
                
                # Remove None values and duplicates
                cookie_info = {k: v for k, v in cookie_info.items() if v is not None}
                
                # Check if we already have this cookie from headers
                if not any(c['name'] == cookie.name for c in laravel_cookies):
                    laravel_cookies.append(cookie_info)
        
    except Exception:
        pass
    
    return laravel_cookies


def _parse_cookie_header(cookie_header: str) -> Optional[Dict[str, Union[str, bool]]]:
    """
    Parse a Set-Cookie header string.
    
    Args:
        cookie_header: Raw Set-Cookie header string
        
    Returns:
        Optional[Dict]: Parsed cookie information
    """
    try:
        # Split cookie attributes
        parts = cookie_header.split(';')
        if not parts:
            return None
        
        # Extract name and value from first part
        name_value = parts[0].strip().split('=', 1)
        if len(name_value) != 2:
            return None
        
        cookie_info = {
            'name': name_value[0].strip(),
            'httponly': False,
            'secure': False,
            'samesite': None,
            'domain': None,
            'path': None
        }
        
        # Parse attributes
        for part in parts[1:]:
            part = part.strip().lower()
            
            if part == 'httponly':
                cookie_info['httponly'] = True
            elif part == 'secure':
                cookie_info['secure'] = True
            elif part.startswith('samesite='):
                cookie_info['samesite'] = part.split('=', 1)[1]
            elif part.startswith('domain='):
                cookie_info['domain'] = part.split('=', 1)[1]
            elif part.startswith('path='):
                cookie_info['path'] = part.split('=', 1)[1]
        
        # Remove None values
        cookie_info = {k: v for k, v in cookie_info.items() if v is not None}
        
        return cookie_info
        
    except Exception:
        return None


def scan_detailed(target_url: str) -> Optional[Dict[str, Union[str, List[Dict], Dict]]]:
    """
    Perform detailed scan with security analysis of Laravel tokens.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Detailed token analysis
    """
    if not target_url:
        return None
    
    try:
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        target_url = target_url.rstrip('/')
        
        response = requests.get(
            target_url,
            timeout=10,
            allow_redirects=True
        )
        
        laravel_cookies = _extract_laravel_cookies(response)
        
        if laravel_cookies:
            # Analyze security implications
            security_analysis = _analyze_cookie_security(laravel_cookies, target_url)
            
            return {
                "url": target_url,
                "cookies": laravel_cookies,
                "security_analysis": security_analysis,
                "total_cookies": len(laravel_cookies)
            }
        
    except Exception:
        pass
    
    return None


def _analyze_cookie_security(cookies: List[Dict], target_url: str) -> Dict[str, Union[List[str], int]]:
    """
    Analyze security implications of Laravel cookies.
    
    Args:
        cookies: List of cookie dictionaries
        target_url: The target URL being scanned
        
    Returns:
        Dict: Security analysis results
    """
    analysis = {
        "security_issues": [],
        "recommendations": [],
        "risk_level": "low"
    }
    
    try:
        is_https = target_url.startswith('https://')
        
        for cookie in cookies:
            cookie_name = cookie.get('name', '')
            
            # Check for security issues
            if cookie_name == 'XSRF-TOKEN' and cookie.get('httponly', False):
                analysis["security_issues"].append(f"{cookie_name} cookie is HttpOnly (should be accessible to JavaScript)")
            
            if not cookie.get('secure', False) and is_https:
                analysis["security_issues"].append(f"{cookie_name} cookie missing Secure flag on HTTPS site")
            
            if not cookie.get('samesite'):
                analysis["security_issues"].append(f"{cookie_name} cookie missing SameSite attribute")
            
            if cookie_name == 'laravel_session' and not cookie.get('httponly', False):
                analysis["security_issues"].append(f"{cookie_name} session cookie not HttpOnly")
        
        # Generate recommendations
        if any('missing Secure flag' in issue for issue in analysis["security_issues"]):
            analysis["recommendations"].append("Enable Secure flag for all cookies on HTTPS sites")
        
        if any('missing SameSite' in issue for issue in analysis["security_issues"]):
            analysis["recommendations"].append("Set SameSite attribute to 'Lax' or 'Strict' for CSRF protection")
        
        if any('not HttpOnly' in issue and 'laravel_session' in issue for issue in analysis["security_issues"]):
            analysis["recommendations"].append("Enable HttpOnly flag for session cookies")
        
        # Determine risk level
        issue_count = len(analysis["security_issues"])
        if issue_count == 0:
            analysis["risk_level"] = "low"
        elif issue_count <= 2:
            analysis["risk_level"] = "medium"
        else:
            analysis["risk_level"] = "high"
        
    except Exception:
        pass
    
    return analysis


def scan_multiple_pages(target_url: str) -> Optional[Dict[str, Union[str, List[Dict], Dict]]]:
    """
    Scan multiple pages for Laravel token exposure.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Comprehensive token analysis across multiple pages
    """
    if not target_url:
        return None
    
    try:
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        target_url = target_url.rstrip('/')
        
        # Pages to check for token exposure
        test_pages = [
            '/',
            '/login',
            '/register',
            '/home',
            '/dashboard'
        ]
        
        all_cookies = []
        pages_with_tokens = []
        
        for page in test_pages:
            try:
                full_url = target_url + page
                response = requests.get(full_url, timeout=5, allow_redirects=True)
                
                page_cookies = _extract_laravel_cookies(response)
                if page_cookies:
                    pages_with_tokens.append({
                        "page": page,
                        "url": full_url,
                        "cookies": page_cookies
                    })
                    
                    # Add unique cookies to all_cookies list
                    for cookie in page_cookies:
                        if not any(c['name'] == cookie['name'] for c in all_cookies):
                            all_cookies.append(cookie)
            
            except Exception:
                continue
        
        if all_cookies:
            security_analysis = _analyze_cookie_security(all_cookies, target_url)
            
            return {
                "url": target_url,
                "cookies": all_cookies,
                "pages_with_tokens": pages_with_tokens,
                "security_analysis": security_analysis,
                "total_pages_scanned": len(test_pages),
                "pages_with_tokens_count": len(pages_with_tokens)
            }
        
    except Exception:
        pass
    
    return None


def batch_scan(urls: List[str]) -> List[Dict[str, Union[str, Dict, None]]]:
    """
    Scan multiple URLs for token leakage.
    
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