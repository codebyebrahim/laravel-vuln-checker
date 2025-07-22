#!/usr/bin/env python3
"""
Laravel Environment Backup File Exposure Scanner

This module detects exposed Laravel environment backup files that may contain
sensitive configuration data such as database credentials, API keys, and
application secrets.
"""

import requests
from typing import Dict, List, Optional, Union


def scan(target_url: str) -> Optional[Dict[str, Union[str, int]]]:
    """
    Scan for exposed Laravel environment backup files.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Dictionary with vulnerability details if found, None otherwise
        Format: {"path": "/.env.bak", "url": "https://example.com/.env.bak", "http_status": 200}
    """
    if not target_url:
        return None
    
    try:
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        target_url = target_url.rstrip('/')
        
        # Environment backup file paths to test
        backup_paths = [
            '/.env.bak',
            '/.env.old',
            '/.env.save'
        ]
        
        for path in backup_paths:
            full_url = target_url + path
            
            # Make request with short timeout
            response = requests.get(
                full_url,
                timeout=5,
                allow_redirects=False
            )
            
            # Check if status is 200 and content contains Laravel env variables
            if response.status_code == 200:
                content = response.text
                
                # Check for Laravel environment variable indicators
                env_indicators = [
                    'APP_KEY=',
                    'DB_PASSWORD=',
                    'MAIL_',
                    'AWS_'
                ]
                
                # If any indicator found, mark as exposed
                if any(indicator in content for indicator in env_indicators):
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
    Perform detailed scan with additional environment backup file paths.
    
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
        
        # Extended list of environment backup file paths
        extended_backup_paths = [
            '/.env.bak',
            '/.env.old',
            '/.env.save',
            '/.env.backup',
            '/.env.orig',
            '/.env.copy',
            '/.env.tmp',
            '/.env~',
            '/env.bak',
            '/env.old'
        ]
        
        found_variables = []
        
        for path in extended_backup_paths:
            full_url = target_url + path
            
            response = requests.get(
                full_url,
                timeout=5,
                allow_redirects=False
            )
            
            if response.status_code == 200:
                content = response.text
                
                # Check for Laravel environment variables
                env_indicators = [
                    'APP_KEY=',
                    'APP_NAME=',
                    'DB_PASSWORD=',
                    'DB_USERNAME=',
                    'MAIL_PASSWORD=',
                    'MAIL_USERNAME=',
                    'AWS_ACCESS_KEY_ID=',
                    'AWS_SECRET_ACCESS_KEY='
                ]
                
                # Find which variables are present
                for indicator in env_indicators:
                    if indicator in content:
                        found_variables.append(indicator.rstrip('='))
                
                if found_variables:
                    return {
                        "path": path,
                        "url": full_url,
                        "http_status": response.status_code,
                        "found_variables": found_variables,
                        "content_size": len(content)
                    }
        
    except Exception:
        pass
    
    return None


def batch_scan(urls: List[str]) -> List[Dict[str, Union[str, Dict, None]]]:
    """
    Scan multiple URLs for environment backup file exposure.
    
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