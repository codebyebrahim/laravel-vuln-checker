#!/usr/bin/env python3
"""
Laravel Environment File Exposure Scanner

This module scans for exposed Laravel environment files that may contain
sensitive configuration data such as database credentials, API keys, and
application secrets.
"""

import requests
from urllib.parse import urljoin
from typing import Dict, List, Optional, Union


def scan(target_url: str) -> Optional[Dict[str, Union[str, List[str]]]]:
    """
    Scan for exposed Laravel environment files.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Dictionary with vulnerability details if found, None otherwise
        Format: {"path": "/.env", "status": "exposed", "variables": ["APP_KEY", "DB_PASSWORD"]}
    """
    if not target_url:
        return None
    
    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    # Remove trailing slash for consistent path joining
    target_url = target_url.rstrip('/')
    
    # Common .env file paths to check
    env_paths = [
        '/.env',
        '/.env.backup',
        '/.env.dev',
        '/.env.local',
        '/backup/.env'
    ]
    
    for path in env_paths:
        try:
            full_url = urljoin(target_url, path)
            response = requests.get(full_url, timeout=10, allow_redirects=False)
            
            # Check if we got a successful response
            if response.status_code == 200:
                content = response.text
                
                # Check for Laravel environment variables
                found_variables = _check_laravel_env_variables(content)
                
                if found_variables:
                    return {
                        "path": path,
                        "status": "exposed",
                        "variables": found_variables,
                        "url": full_url,
                        "size": len(content)
                    }
                    
        except Exception:
            # Silently continue to next path on any error
            continue
    
    return None


def _check_laravel_env_variables(content: str) -> List[str]:
    """
    Check content for Laravel environment variables.
    
    Args:
        content (str): The response content to analyze
        
    Returns:
        List[str]: List of found Laravel environment variable prefixes
    """
    found_variables = []
    
    # Laravel environment variable patterns to look for
    laravel_env_patterns = [
        'APP_KEY=',
        'APP_NAME=',
        'APP_ENV=',
        'APP_DEBUG=',
        'APP_URL=',
        'DB_CONNECTION=',
        'DB_HOST=',
        'DB_PORT=',
        'DB_DATABASE=',
        'DB_USERNAME=',
        'DB_PASSWORD=',
        'MAIL_MAILER=',
        'MAIL_HOST=',
        'MAIL_PORT=',
        'MAIL_USERNAME=',
        'MAIL_PASSWORD=',
        'MAIL_ENCRYPTION=',
        'MAIL_FROM_ADDRESS=',
        'REDIS_HOST=',
        'REDIS_PASSWORD=',
        'REDIS_PORT=',
        'AWS_ACCESS_KEY_ID=',
        'AWS_SECRET_ACCESS_KEY=',
        'AWS_DEFAULT_REGION=',
        'AWS_BUCKET=',
        'PUSHER_APP_ID=',
        'PUSHER_APP_KEY=',
        'PUSHER_APP_SECRET=',
        'SESSION_DRIVER=',
        'SESSION_LIFETIME=',
        'QUEUE_CONNECTION=',
        'CACHE_DRIVER=',
        'FILESYSTEM_DISK=',
        'LOG_CHANNEL=',
        'LOG_DEPRECATIONS_CHANNEL=',
        'LOG_LEVEL='
    ]
    
    # Check each pattern
    for pattern in laravel_env_patterns:
        if pattern in content:
            # Extract just the variable name (remove the '=' part)
            var_name = pattern.rstrip('=')
            if var_name not in found_variables:
                found_variables.append(var_name)
    
    return found_variables


def scan_detailed(target_url: str) -> Optional[Dict[str, Union[str, List[str], Dict]]]:
    """
    Perform a detailed scan with additional information about found variables.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Detailed dictionary with vulnerability information
    """
    if not target_url:
        return None
    
    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    target_url = target_url.rstrip('/')
    
    env_paths = [
        '/.env',
        '/.env.backup',
        '/.env.dev',
        '/.env.local',
        '/backup/.env'
    ]
    
    for path in env_paths:
        try:
            full_url = urljoin(target_url, path)
            response = requests.get(full_url, timeout=10, allow_redirects=False)
            
            if response.status_code == 200:
                content = response.text
                found_variables = _check_laravel_env_variables(content)
                
                if found_variables:
                    # Categorize variables by sensitivity
                    categorized_vars = _categorize_variables(found_variables)
                    
                    return {
                        "path": path,
                        "status": "exposed",
                        "variables": found_variables,
                        "categorized_variables": categorized_vars,
                        "url": full_url,
                        "size": len(content),
                        "response_headers": dict(response.headers),
                        "total_variables": len(found_variables)
                    }
                    
        except Exception:
            continue
    
    return None


def _categorize_variables(variables: List[str]) -> Dict[str, List[str]]:
    """
    Categorize environment variables by sensitivity level.
    
    Args:
        variables (List[str]): List of found environment variables
        
    Returns:
        Dict[str, List[str]]: Categorized variables
    """
    categories = {
        "critical": [],      # Database passwords, API keys, secrets
        "sensitive": [],     # Database configs, mail configs
        "informational": []  # App name, environment, debug settings
    }
    
    critical_patterns = [
        'DB_PASSWORD', 'MAIL_PASSWORD', 'REDIS_PASSWORD', 
        'AWS_SECRET_ACCESS_KEY', 'APP_KEY', 'PUSHER_APP_SECRET'
    ]
    
    sensitive_patterns = [
        'DB_HOST', 'DB_DATABASE', 'DB_USERNAME', 'DB_CONNECTION',
        'MAIL_HOST', 'MAIL_USERNAME', 'AWS_ACCESS_KEY_ID', 
        'PUSHER_APP_ID', 'PUSHER_APP_KEY'
    ]
    
    for var in variables:
        if var in critical_patterns:
            categories["critical"].append(var)
        elif var in sensitive_patterns:
            categories["sensitive"].append(var)
        else:
            categories["informational"].append(var)
    
    return categories


def batch_scan(urls: List[str]) -> List[Dict[str, Union[str, Dict, None]]]:
    """
    Scan multiple URLs for environment file exposure.
    
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