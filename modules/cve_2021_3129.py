#!/usr/bin/env python3
"""
Laravel Ignition RCE Vulnerability Scanner (CVE-2021-3129)

This module detects the presence of Laravel's Ignition RCE vulnerability
by testing specific endpoints with crafted payloads and analyzing responses
for vulnerability indicators.
"""

import requests
import json
from urllib.parse import urljoin
from typing import Dict, List, Optional, Union


def scan(target_url: str) -> Optional[Dict[str, Union[str, int]]]:
    """
    Scan for Laravel Ignition RCE vulnerability (CVE-2021-3129).
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Dictionary with vulnerability details if found, None otherwise
        Format: {"path": "/__ignition/execute-solution", "status": "vulnerable", "http_status": 200}
    """
    if not target_url:
        return None
    
    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    # Remove trailing slash for consistent path joining
    target_url = target_url.rstrip('/')
    
    # Ignition endpoints to test
    ignition_endpoints = [
        '/_ignition/execute-solution',
        '/__ignition/execute-solution'
    ]
    
    # Test payload for CVE-2021-3129
    payload = {
        "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
        "parameters": {
            "variableName": "username"
        }
    }
    
    # Request headers
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    for endpoint in ignition_endpoints:
        try:
            full_url = urljoin(target_url, endpoint)
            
            response = requests.post(
                full_url,
                json=payload,
                headers=headers,
                timeout=10,
                allow_redirects=False
            )
            
            # Check if response indicates vulnerability
            if _is_vulnerable_response(response):
                return {
                    "path": endpoint,
                    "status": "vulnerable",
                    "http_status": response.status_code,
                    "url": full_url
                }
                
        except Exception:
            # Silently continue to next endpoint on any error
            continue
    
    return None


def _is_vulnerable_response(response: requests.Response) -> bool:
    """
    Analyze response to determine if it indicates vulnerability.
    
    Args:
        response: The HTTP response object
        
    Returns:
        bool: True if response indicates vulnerability
    """
    # Check for expected HTTP status codes
    if response.status_code not in [200, 500]:
        return False
    
    try:
        content = response.text.lower()
        
        # Primary vulnerability indicators
        vulnerability_indicators = [
            '"exception"',
            '"solution"',
            'ignition',
            'laravel',
            'illuminate\\',
            'symfony\\',
            'stack trace',
            'makeviewvariableoptionalsolution',
            'facade\\ignition'
        ]
        
        # Check if any vulnerability indicators are present
        if any(indicator in content for indicator in vulnerability_indicators):
            return True
        
        # Check for Laravel error patterns
        laravel_error_patterns = [
            'app\\exceptions\\handler',
            'bootstrap/app.php',
            'vendor/laravel',
            'artisan',
            'blade.php'
        ]
        
        if any(pattern in content for pattern in laravel_error_patterns):
            return True
        
        # Check for JSON response with specific fields
        try:
            json_response = response.json()
            if isinstance(json_response, dict):
                json_keys = [key.lower() for key in json_response.keys()]
                if any(key in ['exception', 'solution', 'message', 'trace'] for key in json_keys):
                    return True
        except (json.JSONDecodeError, ValueError):
            pass
            
    except Exception:
        pass
    
    return False


def scan_detailed(target_url: str) -> Optional[Dict[str, Union[str, int, Dict, List]]]:
    """
    Perform detailed scan with additional response information.
    
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
    
    target_url = target_url.rstrip('/')
    
    ignition_endpoints = [
        '/_ignition/execute-solution',
        '/__ignition/execute-solution'
    ]
    
    payload = {
        "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
        "parameters": {
            "variableName": "username"
        }
    }
    
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    for endpoint in ignition_endpoints:
        try:
            full_url = urljoin(target_url, endpoint)
            
            response = requests.post(
                full_url,
                json=payload,
                headers=headers,
                timeout=10,
                allow_redirects=False
            )
            
            if _is_vulnerable_response(response):
                # Extract vulnerability indicators found
                indicators = _extract_vulnerability_indicators(response.text)
                
                return {
                    "path": endpoint,
                    "status": "vulnerable",
                    "http_status": response.status_code,
                    "url": full_url,
                    "response_size": len(response.content),
                    "response_headers": dict(response.headers),
                    "vulnerability_indicators": indicators,
                    "content_type": response.headers.get('content-type', ''),
                    "server": response.headers.get('server', '')
                }
                
        except Exception:
            continue
    
    return None


def _extract_vulnerability_indicators(content: str) -> List[str]:
    """
    Extract specific vulnerability indicators from response content.
    
    Args:
        content (str): Response content to analyze
        
    Returns:
        List[str]: List of found vulnerability indicators
    """
    indicators_found = []
    content_lower = content.lower()
    
    indicator_patterns = {
        'exception_field': '"exception"',
        'solution_field': '"solution"',
        'ignition_reference': 'ignition',
        'laravel_framework': 'laravel',
        'illuminate_namespace': 'illuminate\\',
        'symfony_component': 'symfony\\',
        'stack_trace': 'stack trace',
        'solution_class': 'makeviewvariableoptionalsolution',
        'facade_ignition': 'facade\\ignition',
        'laravel_error': 'app\\exceptions\\handler'
    }
    
    for indicator_name, pattern in indicator_patterns.items():
        if pattern in content_lower:
            indicators_found.append(indicator_name)
    
    return indicators_found


def test_alternative_payloads(target_url: str) -> Optional[Dict[str, Union[str, int, List]]]:
    """
    Test alternative payloads for more comprehensive detection.
    
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
    
    target_url = target_url.rstrip('/')
    
    # Alternative payloads to test
    alternative_payloads = [
        {
            "name": "standard_payload",
            "data": {
                "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
                "parameters": {"variableName": "username"}
            }
        },
        {
            "name": "alternative_solution",
            "data": {
                "solution": "Facade\\Ignition\\Solutions\\GenerateConfigCacheSolution",
                "parameters": {}
            }
        },
        {
            "name": "empty_parameters",
            "data": {
                "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
                "parameters": {}
            }
        }
    ]
    
    endpoints = ['/_ignition/execute-solution', '/__ignition/execute-solution']
    headers = {"Content-Type": "application/json"}
    
    for endpoint in endpoints:
        for payload_info in alternative_payloads:
            try:
                full_url = urljoin(target_url, endpoint)
                
                response = requests.post(
                    full_url,
                    json=payload_info["data"],
                    headers=headers,
                    timeout=10,
                    allow_redirects=False
                )
                
                if _is_vulnerable_response(response):
                    return {
                        "path": endpoint,
                        "status": "vulnerable",
                        "http_status": response.status_code,
                        "url": full_url,
                        "successful_payload": payload_info["name"],
                        "payload_data": payload_info["data"]
                    }
                    
            except Exception:
                continue
    
    return None


def batch_scan(urls: List[str]) -> List[Dict[str, Union[str, Dict, None]]]:
    """
    Scan multiple URLs for CVE-2021-3129 vulnerability.
    
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
