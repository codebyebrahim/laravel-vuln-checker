#!/usr/bin/env python3
"""
Laravel Debug Tools Exposure Scanner

This module detects publicly exposed Laravel debug and admin tools that
should typically be restricted to development environments or authorized
users only.
"""

import requests
from typing import Dict, List, Optional, Union


def scan(target_url: str) -> Optional[List[Dict[str, Union[str, int]]]]:
    """
    Scan for exposed Laravel debug and admin tools.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[List[Dict]]: List of exposed tools if found, None otherwise
        Format: [{"path": "/telescope", "url": "https://example.com/telescope", "tool": "Telescope", "status": 200}]
    """
    if not target_url:
        return None
    
    try:
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        target_url = target_url.rstrip('/')
        
        # Debug tool paths to test
        debug_tools = [
            {'path': '/_debugbar', 'tool': 'Debugbar', 'indicators': ['Debugbar', 'phpdebugbar', 'debugbar']},
            {'path': '/debugbar', 'tool': 'Debugbar', 'indicators': ['Debugbar', 'phpdebugbar', 'debugbar']},
            {'path': '/telescope', 'tool': 'Telescope', 'indicators': ['Laravel Telescope', 'Telescope', 'telescope']},
            {'path': '/horizon', 'tool': 'Horizon', 'indicators': ['Laravel Horizon', 'Horizon', 'horizon']},
            {'path': '/nova', 'tool': 'Nova', 'indicators': ['Nova', 'Laravel Nova', 'nova']}
        ]
        
        exposed_tools = []
        
        for tool_info in debug_tools:
            path = tool_info['path']
            tool_name = tool_info['tool']
            indicators = tool_info['indicators']
            
            full_url = target_url + path
            
            # Make request with short timeout
            response = requests.get(
                full_url,
                timeout=5,
                allow_redirects=False
            )
            
            # Check if status is 200 and content contains tool indicators
            if response.status_code == 200:
                content = response.text
                
                # If any indicator found, mark as exposed
                if any(indicator in content for indicator in indicators):
                    exposed_tools.append({
                        "path": path,
                        "url": full_url,
                        "tool": tool_name,
                        "status": response.status_code
                    })
        
        # Return list if any tools found, None otherwise
        return exposed_tools if exposed_tools else None
        
    except Exception:
        # Silently handle all exceptions
        pass
    
    return None


def scan_detailed(target_url: str) -> Optional[List[Dict[str, Union[str, int, List]]]]:
    """
    Perform detailed scan with additional debug tool paths and analysis.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[List[Dict]]: Detailed list of exposed tools
    """
    if not target_url:
        return None
    
    try:
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        target_url = target_url.rstrip('/')
        
        # Extended debug tool paths
        extended_debug_tools = [
            {'path': '/_debugbar', 'tool': 'Debugbar', 'indicators': ['Debugbar', 'phpdebugbar', 'debugbar']},
            {'path': '/debugbar', 'tool': 'Debugbar', 'indicators': ['Debugbar', 'phpdebugbar', 'debugbar']},
            {'path': '/telescope', 'tool': 'Telescope', 'indicators': ['Laravel Telescope', 'Telescope', 'telescope']},
            {'path': '/horizon', 'tool': 'Horizon', 'indicators': ['Laravel Horizon', 'Horizon', 'horizon']},
            {'path': '/nova', 'tool': 'Nova', 'indicators': ['Nova', 'Laravel Nova', 'nova']},
            {'path': '/clockwork', 'tool': 'Clockwork', 'indicators': ['Clockwork', 'clockwork']},
            {'path': '/log-viewer', 'tool': 'Log Viewer', 'indicators': ['Log Viewer', 'Laravel Log Viewer']},
            {'path': '/laravel-logs', 'tool': 'Laravel Logs', 'indicators': ['laravel-logs', 'Laravel Logs']},
            {'path': '/_ignition', 'tool': 'Ignition', 'indicators': ['Ignition', 'ignition', 'Facade\\Ignition']},
            {'path': '/ignition', 'tool': 'Ignition', 'indicators': ['Ignition', 'ignition', 'Facade\\Ignition']}
        ]
        
        exposed_tools = []
        
        for tool_info in extended_debug_tools:
            path = tool_info['path']
            tool_name = tool_info['tool']
            indicators = tool_info['indicators']
            
            full_url = target_url + path
            
            response = requests.get(
                full_url,
                timeout=5,
                allow_redirects=False
            )
            
            if response.status_code == 200:
                content = response.text
                found_indicators = []
                
                # Find which indicators are present
                for indicator in indicators:
                    if indicator in content:
                        found_indicators.append(indicator)
                
                if found_indicators:
                    exposed_tools.append({
                        "path": path,
                        "url": full_url,
                        "tool": tool_name,
                        "status": response.status_code,
                        "found_indicators": found_indicators,
                        "content_size": len(content)
                    })
        
        return exposed_tools if exposed_tools else None
        
    except Exception:
        pass
    
    return None


def scan_authentication_status(target_url: str) -> Optional[List[Dict[str, Union[str, int, bool]]]]:
    """
    Check if exposed debug tools require authentication.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[List[Dict]]: List of tools with authentication status
    """
    if not target_url:
        return None
    
    try:
        # First run basic scan
        basic_results = scan(target_url)
        if not basic_results:
            return None
        
        authenticated_tools = []
        
        for tool in basic_results:
            full_url = tool['url']
            
            response = requests.get(
                full_url,
                timeout=5,
                allow_redirects=False
            )
            
            if response.status_code == 200:
                content = response.text.lower()
                
                # Check for authentication indicators
                auth_indicators = [
                    'login',
                    'password',
                    'authentication',
                    'signin',
                    'unauthorized',
                    'csrf',
                    'token'
                ]
                
                requires_auth = any(indicator in content for indicator in auth_indicators)
                
                authenticated_tools.append({
                    "path": tool['path'],
                    "url": full_url,
                    "tool": tool['tool'],
                    "status": response.status_code,
                    "requires_authentication": requires_auth,
                    "publicly_accessible": not requires_auth
                })
        
        return authenticated_tools if authenticated_tools else None
        
    except Exception:
        pass
    
    return None


def batch_scan(urls: List[str]) -> List[Dict[str, Union[str, List, None]]]:
    """
    Scan multiple URLs for debug tools exposure.
    
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