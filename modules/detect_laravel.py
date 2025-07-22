#!/usr/bin/env python3
"""
Laravel Detection Module

This module provides functionality to detect if a website is built with Laravel
by checking for common Laravel indicators such as cookies, debug pages, 
common paths, and HTTP headers.
"""

import requests
from urllib.parse import urljoin, urlparse
from typing import List, Tuple


def is_laravel(url: str) -> bool:
    """
    Detect if a website is built with Laravel by checking various indicators.
    
    Args:
        url (str): The target URL to check
        
    Returns:
        bool: True if Laravel indicators are found, False otherwise
    """
    if not url:
        return False
    
    # Normalize URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        # Check main page for Laravel indicators
        if _check_main_page(url):
            return True
        
        # Check for Laravel-specific paths
        if _check_laravel_paths(url):
            return True
        
        # Check for .env file (optional check)
        if _check_env_file(url):
            return True
            
    except Exception:
        # Silently handle any network or parsing errors
        pass
    
    return False


def _check_main_page(url: str) -> bool:
    """
    Check the main page for Laravel indicators.
    
    Args:
        url (str): The base URL to check
        
    Returns:
        bool: True if Laravel indicators found
    """
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        
        # Check for laravel_session cookie
        if 'laravel_session' in response.cookies:
            return True
        
        # Check response headers for Laravel indicators
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        if 'x-powered-by' in headers and 'laravel' in headers['x-powered-by']:
            return True
        
        # Check for Laravel debug page elements in content
        content = response.text.lower()
        debug_indicators = [
            'whoops',
            'stack trace',
            'laravel',
            'illuminate\\',
            'symfony\\',
            'app/http/controllers',
            'vendor/laravel',
            'bootstrap/app.php'
        ]
        
        if any(indicator in content for indicator in debug_indicators):
            return True
            
    except Exception:
        pass
    
    return False


def _check_laravel_paths(url: str) -> bool:
    """
    Check common Laravel paths for existence and Laravel indicators.
    
    Args:
        url (str): The base URL to check
        
    Returns:
        bool: True if Laravel indicators found in common paths
    """
    common_paths = [
        '/login',
        '/register',
        '/api/user',
        '/home',
        '/dashboard',
        '/admin'
    ]
    
    for path in common_paths:
        try:
            full_url = urljoin(url, path)
            response = requests.get(full_url, timeout=5, allow_redirects=True)
            
            # Check for laravel_session cookie
            if 'laravel_session' in response.cookies:
                return True
            
            # Check headers
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            if 'x-powered-by' in headers and 'laravel' in headers['x-powered-by']:
                return True
            
            # Check for Laravel-specific content
            content = response.text.lower()
            laravel_indicators = [
                'csrf-token',
                'laravel',
                'illuminate\\',
                '_token',
                'app.blade.php',
                'layouts.app'
            ]
            
            if any(indicator in content for indicator in laravel_indicators):
                return True
                
        except Exception:
            continue
    
    return False


def _check_env_file(url: str) -> bool:
    """
    Check for the existence of .env file (development environments).
    
    Args:
        url (str): The base URL to check
        
    Returns:
        bool: True if .env file is accessible
    """
    env_paths = [
        '/.env',
        '/.env.example',
        '/.env.local'
    ]
    
    for path in env_paths:
        try:
            full_url = urljoin(url, path)
            response = requests.get(full_url, timeout=5)
            
            # Check if we get a successful response and content looks like env file
            if response.status_code == 200:
                content = response.text.lower()
                env_indicators = [
                    'app_name',
                    'app_env',
                    'app_key',
                    'db_connection',
                    'mail_mailer',
                    'laravel'
                ]
                
                if any(indicator in content for indicator in env_indicators):
                    return True
                    
        except Exception:
            continue
    
    return False


# Additional utility function for batch checking
def check_multiple_urls(urls: List[str]) -> List[Tuple[str, bool]]:
    """
    Check multiple URLs for Laravel indicators.
    
    Args:
        urls (List[str]): List of URLs to check
        
    Returns:
        List[Tuple[str, bool]]: List of (url, is_laravel) tuples
    """
    results = []
    for url in urls:
        result = is_laravel(url)
        results.append((url, result))
    return results