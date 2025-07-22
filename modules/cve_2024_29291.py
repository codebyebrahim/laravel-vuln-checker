#!/usr/bin/env python3
"""
Laravel Debug Mode Exposure Vulnerability Scanner (CVE-2024-29291)

This module detects Laravel debug mode exposure by testing common debug
endpoints and analyzing responses for sensitive information disclosure
such as phpinfo(), debug pages, and error information.
"""

import requests
from urllib.parse import urljoin
from typing import Dict, List, Optional, Union


def scan(target_url: str) -> Optional[Dict[str, Union[str, int]]]:
    """
    Scan for Laravel debug mode exposure vulnerability (CVE-2024-29291).
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Dictionary with vulnerability details if found, None otherwise
        Format: {"path": "/phpinfo", "url": "https://example.com/phpinfo", "status": "exposed", "http_status": 200}
    """
    if not target_url:
        return None
    
    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    # Remove trailing slash for consistent path joining
    target_url = target_url.rstrip('/')
    
    # Debug paths to test
    debug_paths = [
        '/debug',
        '/phpinfo',
        '/info',
        '/test'
    ]
    
    for path in debug_paths:
        try:
            full_url = urljoin(target_url, path)
            
            response = requests.get(
                full_url,
                timeout=10,
                allow_redirects=True
            )
            
            # Check if response indicates debug mode exposure
            if _is_debug_exposed(response):
                return {
                    "path": path,
                    "url": full_url,
                    "status": "exposed",
                    "http_status": response.status_code
                }
                
        except Exception:
            # Silently continue to next path on any error
            continue
    
    return None


def _is_debug_exposed(response: requests.Response) -> bool:
    """
    Analyze response to determine if debug information is exposed.
    
    Args:
        response: The HTTP response object
        
    Returns:
        bool: True if debug information exposure is detected
    """
    # Must have successful status code
    if response.status_code != 200:
        return False
    
    try:
        content = response.text
        content_lower = content.lower()
        
        # Check for explicit debug indicators
        debug_indicators = [
            'phpinfo()',
            'php version',
            '<title>whoops',
            'whoops\\',
            'laravel debug',
            'app_debug',
            'debug mode'
        ]
        
        # Primary check: explicit debug content
        if any(indicator in content_lower for indicator in debug_indicators):
            return True
        
        # Secondary check: suspicious large HTML response
        if _is_suspicious_response(response):
            # Additional checks for potential debug content
            secondary_indicators = [
                'configuration',
                'environment',
                'server information',
                'php configuration',
                'loaded modules',
                'system',
                'variables',
                '$_server',
                '$_env',
                'apache',
                'nginx',
                'memory_limit',
                'upload_max_filesize'
            ]
            
            # Count secondary indicators
            indicator_count = sum(1 for indicator in secondary_indicators if indicator in content_lower)
            
            # If multiple secondary indicators present, likely debug page
            if indicator_count >= 3:
                return True
        
    except Exception:
        pass
    
    return False


def _is_suspicious_response(response: requests.Response) -> bool:
    """
    Check if response characteristics suggest debug information exposure.
    
    Args:
        response: The HTTP response object
        
    Returns:
        bool: True if response characteristics are suspicious
    """
    try:
        # Check content type is HTML
        content_type = response.headers.get('content-type', '').lower()
        if 'text/html' not in content_type:
            return False
        
        # Check response size is substantial (> 1KB)
        content_length = len(response.content)
        if content_length <= 1024:  # 1KB threshold
            return False
        
        return True
        
    except Exception:
        return False


def scan_detailed(target_url: str) -> Optional[Dict[str, Union[str, int, Dict, List]]]:
    """
    Perform detailed scan with comprehensive analysis of debug exposure.
    
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
    
    debug_paths = [
        '/debug',
        '/phpinfo',
        '/info',
        '/test'
    ]
    
    for path in debug_paths:
        try:
            full_url = urljoin(target_url, path)
            response = requests.get(full_url, timeout=10, allow_redirects=True)
            
            if _is_debug_exposed(response):
                # Extract detailed information about exposure
                exposure_details = _analyze_debug_exposure(response)
                
                return {
                    "path": path,
                    "url": full_url,
                    "status": "exposed",
                    "http_status": response.status_code,
                    "response_size": len(response.content),
                    "content_type": response.headers.get('content-type', ''),
                    "exposure_details": exposure_details,
                    "response_headers": dict(response.headers),
                    "server": response.headers.get('server', '')
                }
                
        except Exception:
            continue
    
    return None


def _analyze_debug_exposure(response: requests.Response) -> Dict[str, Union[bool, List[str]]]:
    """
    Analyze the type and severity of debug information exposure.
    
    Args:
        response: The HTTP response object
        
    Returns:
        Dict: Analysis of exposed debug information
    """
    analysis = {
        "phpinfo_detected": False,
        "whoops_detected": False,
        "laravel_debug_detected": False,
        "environment_variables": False,
        "server_information": False,
        "exposed_indicators": []
    }
    
    try:
        content = response.text.lower()
        
        # Check for specific exposure types
        if 'phpinfo()' in content or 'php version' in content:
            analysis["phpinfo_detected"] = True
            analysis["exposed_indicators"].append("PHP configuration information")
        
        if 'whoops' in content or '<title>whoops' in content:
            analysis["whoops_detected"] = True
            analysis["exposed_indicators"].append("Laravel Whoops error page")
        
        if 'laravel debug' in content or 'app_debug' in content:
            analysis["laravel_debug_detected"] = True
            analysis["exposed_indicators"].append("Laravel debug mode active")
        
        if '$_env' in content or 'environment' in content:
            analysis["environment_variables"] = True
            analysis["exposed_indicators"].append("Environment variables")
        
        if '$_server' in content or 'server information' in content:
            analysis["server_information"] = True
            analysis["exposed_indicators"].append("Server configuration")
        
        # Check for additional sensitive information
        sensitive_patterns = [
            ('database credentials', ['db_password', 'database_password', 'mysql_password']),
            ('api keys', ['api_key', 'secret_key', 'access_token']),
            ('file paths', ['/var/www', '/home/', 'document_root']),
            ('system information', ['php_version', 'loaded_modules', 'memory_limit'])
        ]
        
        for category, patterns in sensitive_patterns:
            if any(pattern in content for pattern in patterns):
                analysis["exposed_indicators"].append(category)
        
    except Exception:
        pass
    
    return analysis


def scan_extended_paths(target_url: str) -> Optional[Dict[str, Union[str, int, List]]]:
    """
    Scan extended list of potential debug endpoints.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Vulnerability information with extended path testing
    """
    if not target_url:
        return None
    
    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    target_url = target_url.rstrip('/')
    
    # Extended debug paths to test
    extended_paths = [
        '/debug',
        '/phpinfo',
        '/info',
        '/test',
        '/debug.php',
        '/phpinfo.php',
        '/info.php',
        '/test.php',
        '/_debug',
        '/laravel-debug',
        '/debug-mode',
        '/whoops',
        '/error',
        '/exception'
    ]
    
    for path in extended_paths:
        try:
            full_url = urljoin(target_url, path)
            response = requests.get(full_url, timeout=10, allow_redirects=True)
            
            if _is_debug_exposed(response):
                return {
                    "path": path,
                    "url": full_url,
                    "status": "exposed",
                    "http_status": response.status_code,
                    "tested_paths": extended_paths,
                    "successful_path": path
                }
                
        except Exception:
            continue
    
    return None


def check_error_disclosure(target_url: str) -> Optional[Dict[str, Union[str, int]]]:
    """
    Check for error disclosure by triggering potential errors.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Error disclosure vulnerability information
    """
    if not target_url:
        return None
    
    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    target_url = target_url.rstrip('/')
    
    # Paths likely to trigger errors
    error_trigger_paths = [
        '/nonexistent-page-12345',
        '/admin/test',
        '/api/invalid',
        '/.env',
        '/config',
        '/storage'
    ]
    
    for path in error_trigger_paths:
        try:
            full_url = urljoin(target_url, path)
            response = requests.get(full_url, timeout=10, allow_redirects=True)
            
            # Check for debug information in error responses
            if response.status_code in [404, 500, 403] and _contains_debug_info(response):
                return {
                    "path": path,
                    "url": full_url,
                    "status": "error_disclosure",
                    "http_status": response.status_code
                }
                
        except Exception:
            continue
    
    return None


def _contains_debug_info(response: requests.Response) -> bool:
    """
    Check if error response contains debug information.
    
    Args:
        response: The HTTP response object
        
    Returns:
        bool: True if debug information found in error response
    """
    try:
        content = response.text.lower()
        
        debug_error_indicators = [
            'whoops',
            'laravel',
            'illuminate\\',
            'symfony\\',
            'stack trace',
            'app\\exceptions',
            'vendor/laravel',
            'bootstrap/app.php',
            'artisan'
        ]
        
        return any(indicator in content for indicator in debug_error_indicators)
        
    except Exception:
        return False


def batch_scan(urls: List[str]) -> List[Dict[str, Union[str, Dict, None]]]:
    """
    Scan multiple URLs for debug mode exposure vulnerability.
    
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