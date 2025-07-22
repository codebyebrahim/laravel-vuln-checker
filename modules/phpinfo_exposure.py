#!/usr/bin/env python3
"""
PHPinfo Exposure Scanner

This module detects exposed PHPinfo diagnostic files that may reveal
sensitive server configuration information, PHP settings, and system
details that should not be publicly accessible.
"""

import requests
from typing import Dict, List, Optional, Union


def scan(target_url: str) -> Optional[Dict[str, Union[str, int]]]:
    """
    Scan for exposed PHPinfo diagnostic files.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Dictionary with vulnerability details if found, None otherwise
        Format: {"path": "/phpinfo.php", "url": "https://target.com/phpinfo.php", "http_status": 200}
    """
    if not target_url:
        return None
    
    try:
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        target_url = target_url.rstrip('/')
        
        # PHPinfo file paths to test
        phpinfo_paths = [
            '/phpinfo.php',
            '/info.php',
            '/serverinfo.php',
            '/test.php'
        ]
        
        for path in phpinfo_paths:
            full_url = target_url + path
            
            # Make request with short timeout
            response = requests.get(
                full_url,
                timeout=5,
                allow_redirects=False
            )
            
            # Check if status is 200 and content contains PHPinfo indicators
            if response.status_code == 200:
                content = response.text
                
                # Check for PHPinfo indicators
                phpinfo_indicators = [
                    'phpinfo()',
                    'PHP Version',
                    '<title>phpinfo()'
                ]
                
                # If any indicator found, mark as exposed
                if any(indicator in content for indicator in phpinfo_indicators):
                    return {
                        "path": path,
                        "url": full_url,
                        "http_status": response.status_code
                    }
        
    except Exception:
        # Silently handle all exceptions
        pass
    
    return None


def scan_detailed(target_url: str) -> Optional[Dict[str, Union[str, int, List]]]:
    """
    Perform detailed scan with additional PHPinfo file paths and analysis.
    
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
        
        # Extended list of PHPinfo and diagnostic file paths
        extended_phpinfo_paths = [
            '/phpinfo.php',
            '/info.php',
            '/serverinfo.php',
            '/test.php',
            '/php.php',
            '/pi.php',
            '/i.php',
            '/phpversion.php',
            '/configuration.php',
            '/config.php',
            '/diagnostic.php',
            '/debug.php'
        ]
        
        found_indicators = []
        
        for path in extended_phpinfo_paths:
            full_url = target_url + path
            
            response = requests.get(
                full_url,
                timeout=5,
                allow_redirects=False
            )
            
            if response.status_code == 200:
                content = response.text
                
                # Check for PHPinfo and diagnostic indicators
                diagnostic_indicators = [
                    'phpinfo()',
                    'PHP Version',
                    '<title>phpinfo()',
                    'PHP Credits',
                    'Configuration',
                    'php_uname',
                    'System',
                    'Build Date',
                    'Server API',
                    'Virtual Directory Support'
                ]
                
                # Find which indicators are present
                for indicator in diagnostic_indicators:
                    if indicator in content:
                        found_indicators.append(indicator)
                
                if found_indicators:
                    return {
                        "path": path,
                        "url": full_url,
                        "http_status": response.status_code,
                        "found_indicators": found_indicators,
                        "content_size": len(content)
                    }
        
    except Exception:
        pass
    
    return None


def batch_scan(urls: List[str]) -> List[Dict[str, Union[str, Dict, None]]]:
    """
    Scan multiple URLs for PHPinfo exposure.
    
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