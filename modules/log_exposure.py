#!/usr/bin/env python3
"""
Laravel Log File Exposure Scanner

This module detects exposed Laravel log files that may contain sensitive
error information, stack traces, and application debugging details that
should not be publicly accessible.
"""

import requests
from urllib.parse import urljoin
from typing import Dict, List, Optional, Union


def scan(target_url: str) -> Optional[Dict[str, Union[str, int]]]:
    """
    Scan for exposed Laravel log file vulnerability.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Dictionary with vulnerability details if found, None otherwise
        Format: {"path": "/storage/logs/laravel.log", "url": "https://example.com/storage/logs/laravel.log", "status": "exposed", "http_status": 200}
    """
    if not target_url:
        return None
    
    try:
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        target_url = target_url.rstrip('/')
        
        # Laravel log file path
        log_path = '/storage/logs/laravel.log'
        full_url = target_url + log_path
        
        # Make request with short timeout
        response = requests.get(
            full_url,
            timeout=5,
            allow_redirects=False
        )
        
        # Check if status is 200 and content contains log indicators
        if response.status_code == 200:
            content = response.text
            
            # Check for Laravel log indicators
            log_indicators = [
                'local.ERROR',
                'production.ERROR', 
                'Stack trace',
                '#0',
                '#1'
            ]
            
            # If any indicator found, mark as exposed
            if any(indicator in content for indicator in log_indicators):
                return {
                    "path": log_path,
                    "url": full_url,
                    "status": "exposed",
                    "http_status": response.status_code
                }
        
    except Exception:
        # Silently handle all exceptions
        pass
    
    return None


def _is_log_exposed(response: requests.Response) -> bool:
    """
    Analyze response to determine if Laravel log file is exposed.
    
    Args:
        response: The HTTP response object
        
    Returns:
        bool: True if log file exposure is detected
    """
    # Must have successful status code
    if response.status_code != 200:
        return False
    
    try:
        content = response.text
        
        # Check for Laravel log file indicators
        log_indicators = [
            'local.ERROR:',
            'Stack trace:',
            'production.ERROR:',
            'local.INFO:',
            'production.INFO:',
            'local.WARNING:',
            'production.WARNING:'
        ]
        
        # Primary check: Laravel log format indicators
        if any(indicator in content for indicator in log_indicators):
            return True
        
        # Secondary check: Stack trace line numbers
        lines = content.split('\n')
        for line in lines:
            stripped_line = line.strip()
            # Check for stack trace patterns like "#0", "#1", etc.
            if stripped_line.startswith('#') and len(stripped_line) > 1:
                try:
                    # Check if character after # is a digit
                    if stripped_line[1].isdigit():
                        return True
                except IndexError:
                    continue
        
        # Additional check: Laravel error patterns
        error_patterns = [
            'Illuminate\\',
            'Laravel\\',
            'App\\Exceptions\\',
            'vendor/laravel/',
            'artisan',
            'bootstrap/app.php'
        ]
        
        # If multiple error patterns present, likely a Laravel log
        pattern_count = sum(1 for pattern in error_patterns if pattern in content)
        if pattern_count >= 2:
            return True
        
    except Exception:
        pass
    
    return False


def scan_detailed(target_url: str) -> Optional[Dict[str, Union[str, int, Dict, List]]]:
    """
    Perform detailed scan of log file exposure with comprehensive analysis.
    
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
    
    log_path = '/storage/logs/laravel.log'
    
    try:
        full_url = urljoin(target_url, log_path)
        response = requests.get(full_url, timeout=10, allow_redirects=False)
        
        if _is_log_exposed(response):
            # Extract detailed log information
            log_details = _analyze_log_exposure(response)
            
            return {
                "path": log_path,
                "url": full_url,
                "status": "exposed",
                "http_status": response.status_code,
                "response_size": len(response.content),
                "content_type": response.headers.get('content-type', ''),
                "log_details": log_details,
                "response_headers": dict(response.headers)
            }
            
    except Exception:
        pass
    
    return None


def _analyze_log_exposure(response: requests.Response) -> Dict[str, Union[str, List[str], int]]:
    """
    Analyze the exposed log file for detailed information.
    
    Args:
        response: The HTTP response object
        
    Returns:
        Dict: Analysis of exposed log information
    """
    analysis = {
        "log_level_counts": {},
        "error_types": [],
        "sensitive_info_found": [],
        "total_lines": 0,
        "date_range": "",
        "common_errors": []
    }
    
    try:
        content = response.text
        lines = content.split('\n')
        analysis["total_lines"] = len(lines)
        
        # Count log levels
        log_levels = ['ERROR', 'WARNING', 'INFO', 'DEBUG', 'CRITICAL']
        for level in log_levels:
            count = content.count(f'.{level}:')
            if count > 0:
                analysis["log_level_counts"][level] = count
        
        # Look for specific error types
        error_types = [
            'ErrorException',
            'FatalErrorException', 
            'ParseError',
            'TypeError',
            'RuntimeException',
            'InvalidArgumentException',
            'BadMethodCallException',
            'QueryException'
        ]
        
        for error_type in error_types:
            if error_type in content:
                analysis["error_types"].append(error_type)
        
        # Check for sensitive information
        sensitive_patterns = [
            ('Database credentials', ['DB_PASSWORD', 'database_password', 'mysql_password']),
            ('API keys', ['api_key', 'secret_key', 'access_token']),
            ('File paths', ['/var/www', '/home/', 'storage/app']),
            ('User information', ['user_id', 'email', 'password']),
            ('Environment info', ['APP_KEY', '.env', 'config/app.php'])
        ]
        
        for category, patterns in sensitive_patterns:
            for pattern in patterns:
                if pattern in content:
                    analysis["sensitive_info_found"].append(category)
                    break
        
        # Extract date range
        date_lines = []
        for line in lines[:50]:  # Check first 50 lines for dates
            if '[' in line and ']' in line:
                try:
                    date_part = line.split(']')[0].split('[')[1]
                    if len(date_part) > 10:  # Basic date length check
                        date_lines.append(date_part[:10])  # YYYY-MM-DD
                except:
                    continue
        
        if date_lines:
            analysis["date_range"] = f"{min(date_lines)} to {max(date_lines)}"
        
        # Find common error messages
        error_messages = []
        for line in lines:
            if '.ERROR:' in line or '.WARNING:' in line:
                try:
                    # Extract the error message part
                    error_part = line.split(': ', 2)[-1][:100]  # First 100 chars
                    if error_part and error_part not in error_messages:
                        error_messages.append(error_part)
                        if len(error_messages) >= 5:  # Limit to top 5
                            break
                except:
                    continue
        
        analysis["common_errors"] = error_messages
        
    except Exception:
        pass
    
    return analysis


def scan_multiple_log_files(target_url: str) -> Optional[Dict[str, Union[str, int, List]]]:
    """
    Scan for multiple types of Laravel log files.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Vulnerability information with multiple log file testing
    """
    if not target_url:
        return None
    
    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    target_url = target_url.rstrip('/')
    
    # Common Laravel log file paths
    log_paths = [
        '/storage/logs/laravel.log',
        '/storage/logs/laravel-2024-01-01.log',
        '/storage/logs/laravel-2024-12-01.log',
        '/storage/logs/laravel-2025-01-01.log',
        '/storage/logs/daily.log',
        '/storage/logs/error.log',
        '/storage/logs/access.log',
        '/logs/laravel.log',
        '/logs/error.log',
        '/app/storage/logs/laravel.log'
    ]
    
    exposed_logs = []
    
    for log_path in log_paths:
        try:
            full_url = urljoin(target_url, log_path)
            response = requests.get(full_url, timeout=10, allow_redirects=False)
            
            if _is_log_exposed(response):
                exposed_logs.append({
                    "path": log_path,
                    "url": full_url,
                    "size": len(response.content),
                    "content_type": response.headers.get('content-type', '')
                })
                
                # Return immediately on first confirmed exposure
                return {
                    "path": log_path,
                    "url": full_url,
                    "status": "exposed",
                    "http_status": response.status_code,
                    "exposed_logs": exposed_logs,
                    "total_exposed": len(exposed_logs)
                }
                
        except Exception:
            continue
    
    return None


def check_log_directory_listing(target_url: str) -> Optional[Dict[str, Union[str, int, bool]]]:
    """
    Check if storage/logs directory allows directory listing.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Directory listing vulnerability information
    """
    if not target_url:
        return None
    
    # Normalize URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    target_url = target_url.rstrip('/')
    
    try:
        logs_dir_url = urljoin(target_url, '/storage/logs/')
        response = requests.get(logs_dir_url, timeout=10, allow_redirects=False)
        
        if response.status_code == 200:
            content = response.text.lower()
            
            # Check for directory listing indicators
            directory_indicators = [
                'index of',
                'directory listing',
                'parent directory',
                '<a href="',
                'laravel.log',
                '.log"',
                'last modified'
            ]
            
            # Count indicators
            indicator_count = sum(1 for indicator in directory_indicators if indicator in content)
            
            if indicator_count >= 3:  # Likely directory listing
                return {
                    "path": "/storage/logs/",
                    "url": logs_dir_url,
                    "status": "directory_listing",
                    "http_status": response.status_code,
                    "directory_listing_detected": True
                }
                
    except Exception:
        pass
    
    return None


def extract_sensitive_data(target_url: str) -> Optional[Dict[str, Union[str, List]]]:
    """
    Extract sensitive information from exposed log files.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Extracted sensitive information
    """
    if not target_url:
        return None
    
    # First check if log is exposed
    scan_result = scan(target_url)
    if not scan_result:
        return None
    
    try:
        # Get the full log content
        response = requests.get(scan_result["url"], timeout=15, allow_redirects=False)
        
        if response.status_code == 200:
            content = response.text
            
            sensitive_data = {
                "database_info": [],
                "file_paths": [],
                "user_data": [],
                "api_keys": [],
                "error_details": []
            }
            
            lines = content.split('\n')
            
            # Extract different types of sensitive information
            for line in lines[:500]:  # Limit to first 500 lines for performance
                line_lower = line.lower()
                
                # Database information
                if any(db_term in line_lower for db_term in ['db_', 'database', 'mysql', 'postgres']):
                    if any(sensitive in line_lower for sensitive in ['password', 'user', 'host']):
                        sensitive_data["database_info"].append(line[:200])
                
                # File paths
                if any(path in line for path in ['/var/', '/home/', '/storage/', '/app/']):
                    sensitive_data["file_paths"].append(line[:200])
                
                # User data
                if any(user_term in line_lower for user_term in ['user_id', 'email', 'username']):
                    sensitive_data["user_data"].append(line[:200])
                
                # API keys
                if any(api_term in line_lower for api_term in ['api_key', 'secret', 'token']):
                    sensitive_data["api_keys"].append(line[:200])
                
                # Error details
                if '.ERROR:' in line:
                    sensitive_data["error_details"].append(line[:300])
            
            # Remove duplicates and limit results
            for key in sensitive_data:
                sensitive_data[key] = list(set(sensitive_data[key]))[:10]  # Max 10 per category
            
            return {
                "url": scan_result["url"],
                "sensitive_data": sensitive_data,
                "total_sensitive_items": sum(len(v) for v in sensitive_data.values())
            }
            
    except Exception:
        pass
    
    return None


def batch_scan(urls: List[str]) -> List[Dict[str, Union[str, Dict, None]]]:
    """
    Scan multiple URLs for log file exposure.
    
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