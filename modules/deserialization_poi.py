#!/usr/bin/env python3
"""
PHP Object Injection (POI) Scanner for Laravel Applications

This module detects possible PHP object injection or insecure deserialization
vulnerabilities in Laravel-based web applications by testing various endpoints
with serialized PHP object payloads.
"""

import requests
import json
from typing import Dict, List, Optional, Union


def scan(target_url: str) -> Optional[Dict[str, Union[str, int]]]:
    """
    Scan for PHP Object Injection vulnerabilities in Laravel applications.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Dictionary with vulnerability details if found, None otherwise
        Format: {
            "url": "https://example.com/api/cache",
            "method": "post",
            "payload": "a:1:{i:0;O:8:\"Exploit\":0:{}}",
            "status_code": 500,
            "response_snippet": "PHP Fatal error: unserialize()..."
        }
    """
    if not target_url:
        return None
    
    try:
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        target_url = target_url.rstrip('/')
        
        # Likely endpoints that might process serialized data
        test_endpoints = [
            '/queue/failed',
            '/api/user/session',
            '/api/cache',
            '/api/debug',
            '/laravel/session/test',
            '/api/data',
            '/api/config',
            '/session/store',
            '/cache/store',
            '/api/serialize'
        ]
        
        # PHP object injection payloads
        payloads = [
            'a:1:{i:0;O:8:"Exploit":0:{}}',  # Basic serialized object
            'O:8:"stdClass":0:{}',            # Standard class
            'a:2:{i:0;s:4:"test";i:1;O:8:"Exploit":1:{s:4:"prop";s:5:"value";}}',  # Array with object
            'O:10:"Illuminate":1:{s:4:"data";s:4:"test";}',  # Laravel-like class name
            'a:1:{s:4:"data";O:4:"User":1:{s:2:"id";i:1;}}',  # User object simulation
        ]
        
        # Test each endpoint with different injection methods
        for endpoint in test_endpoints:
            full_url = target_url + endpoint
            
            for payload in payloads:
                # Test POST parameter injection
                result = _test_post_injection(full_url, payload)
                if result:
                    return result
                
                # Test cookie injection
                result = _test_cookie_injection(full_url, payload)
                if result:
                    return result
                
                # Test JSON body injection
                result = _test_json_injection(full_url, payload)
                if result:
                    return result
        
    except Exception:
        # Silently handle all exceptions
        pass
    
    return None


def _test_post_injection(url: str, payload: str) -> Optional[Dict[str, Union[str, int]]]:
    """
    Test PHP object injection via POST parameters.
    
    Args:
        url: Target URL
        payload: Serialized PHP object payload
        
    Returns:
        Optional[Dict]: Vulnerability details if found
    """
    try:
        data = {
            'data': payload,
            'session_data': payload,
            'cache_data': payload,
            'serialize': payload
        }
        
        response = requests.post(
            url,
            data=data,
            timeout=3,
            allow_redirects=False
        )
        
        if _is_vulnerable_response(response):
            return {
                "url": url,
                "method": "post",
                "payload": payload,
                "status_code": response.status_code,
                "response_snippet": response.text[:200]
            }
            
    except Exception:
        pass
    
    return None


def _test_cookie_injection(url: str, payload: str) -> Optional[Dict[str, Union[str, int]]]:
    """
    Test PHP object injection via cookies.
    
    Args:
        url: Target URL
        payload: Serialized PHP object payload
        
    Returns:
        Optional[Dict]: Vulnerability details if found
    """
    try:
        cookies = {
            'laravel_session': payload,
            'XSRF-TOKEN': payload,
            'session_data': payload,
            'cache_key': payload
        }
        
        response = requests.get(
            url,
            cookies=cookies,
            timeout=3,
            allow_redirects=False
        )
        
        if _is_vulnerable_response(response):
            return {
                "url": url,
                "method": "cookie",
                "payload": payload,
                "status_code": response.status_code,
                "response_snippet": response.text[:200]
            }
            
    except Exception:
        pass
    
    return None


def _test_json_injection(url: str, payload: str) -> Optional[Dict[str, Union[str, int]]]:
    """
    Test PHP object injection via JSON body.
    
    Args:
        url: Target URL
        payload: Serialized PHP object payload
        
    Returns:
        Optional[Dict]: Vulnerability details if found
    """
    try:
        json_data = {
            'data': payload,
            'session': payload,
            'cache': payload,
            'serialized_data': payload
        }
        
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        response = requests.post(
            url,
            json=json_data,
            headers=headers,
            timeout=3,
            allow_redirects=False
        )
        
        if _is_vulnerable_response(response):
            return {
                "url": url,
                "method": "json",
                "payload": payload,
                "status_code": response.status_code,
                "response_snippet": response.text[:200]
            }
            
    except Exception:
        pass
    
    return None


def _is_vulnerable_response(response: requests.Response) -> bool:
    """
    Analyze response to determine if it indicates PHP object injection vulnerability.
    
    Args:
        response: HTTP response object
        
    Returns:
        bool: True if response indicates potential vulnerability
    """
    try:
        # Check for error status codes
        if response.status_code == 500:
            content = response.text.lower()
            
            # PHP error keywords indicating deserialization issues
            error_keywords = [
                'unserialize()',
                'object of class',
                'php fatal error',
                'uncaught exception',
                'serialization of',
                '__wakeup',
                '__destruct',
                'notice: unserialize',
                'warning: unserialize',
                'cannot access private property',
                'call to undefined method',
                'class not found'
            ]
            
            # If any error keyword found, likely vulnerable
            if any(keyword in content for keyword in error_keywords):
                return True
        
        # Also check for 200 responses that might contain error information
        elif response.status_code == 200:
            content = response.text.lower()
            
            # Look for specific deserialization error patterns
            deserialization_errors = [
                'unserialize():',
                'object of class',
                'cannot access private property',
                '__wakeup',
                'serialization',
                'php notice: unserialize',
                'php warning: unserialize'
            ]
            
            if any(error in content for error in deserialization_errors):
                return True
        
    except Exception:
        pass
    
    return False


def scan_detailed(target_url: str) -> Optional[Dict[str, Union[str, int, List]]]:
    """
    Perform detailed PHP object injection scan with multiple payloads and methods.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Detailed vulnerability information
    """
    if not target_url:
        return None
    
    try:
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        target_url = target_url.rstrip('/')
        
        vulnerabilities = []
        tested_combinations = 0
        
        # Extended endpoints list
        test_endpoints = [
            '/queue/failed',
            '/api/user/session',
            '/api/cache',
            '/api/debug',
            '/laravel/session/test',
            '/api/data',
            '/api/config',
            '/session/store',
            '/cache/store',
            '/api/serialize',
            '/admin/cache',
            '/admin/session'
        ]
        
        # Extended payloads with different object types
        payloads = [
            'a:1:{i:0;O:8:"Exploit":0:{}}',
            'O:8:"stdClass":0:{}',
            'O:4:"User":1:{s:2:"id";i:1;}',
            'a:2:{s:4:"user";O:4:"User":1:{s:2:"id";i:1;}s:4:"role";s:5:"admin";}',
            'O:10:"Illuminate":2:{s:4:"data";s:4:"test";s:5:"value";i:1;}',
            'a:1:{s:7:"session";O:7:"Session":1:{s:4:"data";s:10:"malicious";}}',
        ]
        
        for endpoint in test_endpoints:
            full_url = target_url + endpoint
            
            for payload in payloads:
                tested_combinations += 1
                
                # Test all injection methods
                methods = [
                    ('post', lambda: _test_post_injection(full_url, payload)),
                    ('cookie', lambda: _test_cookie_injection(full_url, payload)),
                    ('json', lambda: _test_json_injection(full_url, payload))
                ]
                
                for method_name, test_func in methods:
                    result = test_func()
                    if result:
                        vulnerabilities.append(result)
        
        if vulnerabilities:
            return {
                "target_url": target_url,
                "vulnerabilities": vulnerabilities,
                "total_vulnerabilities": len(vulnerabilities),
                "tested_combinations": tested_combinations,
                "vulnerability_summary": _summarize_vulnerabilities(vulnerabilities)
            }
        
    except Exception:
        pass
    
    return None


def _summarize_vulnerabilities(vulnerabilities: List[Dict]) -> Dict[str, Union[List[str], int]]:
    """
    Summarize found vulnerabilities by method and endpoint.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        
    Returns:
        Dict: Summary of vulnerabilities
    """
    summary = {
        "methods": [],
        "endpoints": [],
        "status_codes": []
    }
    
    try:
        for vuln in vulnerabilities:
            method = vuln.get('method', '')
            endpoint = vuln.get('url', '').split('/')[-1]
            status_code = vuln.get('status_code', 0)
            
            if method and method not in summary["methods"]:
                summary["methods"].append(method)
            
            if endpoint and endpoint not in summary["endpoints"]:
                summary["endpoints"].append(endpoint)
            
            if status_code and status_code not in summary["status_codes"]:
                summary["status_codes"].append(status_code)
        
    except Exception:
        pass
    
    return summary


def test_custom_payload(target_url: str, endpoint: str, payload: str) -> Optional[Dict[str, Union[str, int]]]:
    """
    Test a custom PHP object injection payload on a specific endpoint.
    
    Args:
        target_url (str): The target URL
        endpoint (str): Specific endpoint to test
        payload (str): Custom serialized PHP object payload
        
    Returns:
        Optional[Dict]: Vulnerability details if found
    """
    if not target_url or not endpoint or not payload:
        return None
    
    try:
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        target_url = target_url.rstrip('/')
        full_url = target_url + endpoint
        
        # Test all injection methods with custom payload
        methods = [
            ('post', lambda: _test_post_injection(full_url, payload)),
            ('cookie', lambda: _test_cookie_injection(full_url, payload)),
            ('json', lambda: _test_json_injection(full_url, payload))
        ]
        
        for method_name, test_func in methods:
            result = test_func()
            if result:
                return result
        
    except Exception:
        pass
    
    return None


def batch_scan(urls: List[str]) -> List[Dict[str, Union[str, Dict, None]]]:
    """
    Scan multiple URLs for PHP object injection vulnerabilities.
    
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