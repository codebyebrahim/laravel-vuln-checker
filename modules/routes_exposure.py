#!/usr/bin/env python3
"""
Laravel Routes Exposure Scanner

This module detects publicly exposed Laravel route files that may reveal
application structure, endpoint definitions, middleware configurations,
and other sensitive routing information.
"""

import requests
from typing import Dict, List, Optional, Union


def scan(target_url: str) -> Optional[List[Dict[str, Union[str, int]]]]:
    """
    Scan for exposed Laravel route files.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[List[Dict]]: List of exposed route files if found, None otherwise
        Format: [{"path": "/routes/web.php", "url": "https://example.com/routes/web.php", "status": 200}]
    """
    if not target_url:
        return None
    
    try:
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        target_url = target_url.rstrip('/')
        
        # Laravel route file paths to test
        route_paths = [
            '/routes/web.php',
            '/routes/api.php',
            '/routes/channels.php',
            '/routes/console.php',
            '/routes/admin.php'
        ]
        
        exposed_routes = []
        
        for path in route_paths:
            full_url = target_url + path
            
            # Make request with short timeout
            response = requests.get(
                full_url,
                timeout=5,
                allow_redirects=False
            )
            
            # Check if status is 200 and content contains Laravel route indicators
            if response.status_code == 200:
                content = response.text
                
                # Check for Laravel route indicators
                route_indicators = [
                    'Route::',
                    '->middleware(',
                    'use Illuminate\\Support\\Facades\\Route'
                ]
                
                # If any indicator found, mark as exposed
                if any(indicator in content for indicator in route_indicators):
                    exposed_routes.append({
                        "path": path,
                        "url": full_url,
                        "status": response.status_code
                    })
        
        # Return list if any routes found, None otherwise
        return exposed_routes if exposed_routes else None
        
    except Exception:
        # Silently handle all exceptions
        pass
    
    return None


def scan_detailed(target_url: str) -> Optional[List[Dict[str, Union[str, int, List]]]]:
    """
    Perform detailed scan with additional route file paths and analysis.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[List[Dict]]: Detailed list of exposed route files
    """
    if not target_url:
        return None
    
    try:
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        target_url = target_url.rstrip('/')
        
        # Extended route file paths
        extended_route_paths = [
            '/routes/web.php',
            '/routes/api.php',
            '/routes/channels.php',
            '/routes/console.php',
            '/routes/admin.php',
            '/routes/auth.php',
            '/routes/breadcrumbs.php',
            '/routes/custom.php',
            '/app/Http/routes.php',
            '/Http/routes.php'
        ]
        
        exposed_routes = []
        
        for path in extended_route_paths:
            full_url = target_url + path
            
            response = requests.get(
                full_url,
                timeout=5,
                allow_redirects=False
            )
            
            if response.status_code == 200:
                content = response.text
                found_indicators = []
                
                # Extended Laravel route indicators
                route_indicators = [
                    'Route::',
                    '->middleware(',
                    'use Illuminate\\Support\\Facades\\Route',
                    'Route::get(',
                    'Route::post(',
                    'Route::put(',
                    'Route::delete(',
                    'Route::patch(',
                    'Route::group(',
                    'Route::resource(',
                    '->name(',
                    '->where(',
                    'Auth::routes()',
                    'Broadcast::channel('
                ]
                
                # Find which indicators are present
                for indicator in route_indicators:
                    if indicator in content:
                        found_indicators.append(indicator)
                
                if found_indicators:
                    exposed_routes.append({
                        "path": path,
                        "url": full_url,
                        "status": response.status_code,
                        "found_indicators": found_indicators,
                        "content_size": len(content)
                    })
        
        return exposed_routes if exposed_routes else None
        
    except Exception:
        pass
    
    return None


def extract_route_info(target_url: str) -> Optional[List[Dict[str, Union[str, int, Dict]]]]:
    """
    Extract detailed route information from exposed route files.
    
    Args:
        target_url (str): The target URL to scan
        
    Returns:
        Optional[List[Dict]]: List of routes with extracted information
    """
    if not target_url:
        return None
    
    try:
        # First run basic scan
        basic_results = scan(target_url)
        if not basic_results:
            return None
        
        detailed_routes = []
        
        for route_file in basic_results:
            full_url = route_file['url']
            
            response = requests.get(
                full_url,
                timeout=5,
                allow_redirects=False
            )
            
            if response.status_code == 200:
                content = response.text
                
                # Extract route information
                route_info = {
                    "http_methods": [],
                    "middleware_found": [],
                    "controllers_found": [],
                    "route_names": []
                }
                
                lines = content.split('\n')
                
                # Analyze content for route patterns
                for line in lines:
                    line = line.strip()
                    
                    # HTTP methods
                    http_methods = ['get', 'post', 'put', 'patch', 'delete', 'options']
                    for method in http_methods:
                        if f'Route::{method}(' in line:
                            if method.upper() not in route_info["http_methods"]:
                                route_info["http_methods"].append(method.upper())
                    
                    # Middleware
                    if '->middleware(' in line:
                        try:
                            middleware_part = line.split('->middleware(')[1].split(')')[0]
                            middleware_part = middleware_part.replace("'", "").replace('"', '')
                            if middleware_part not in route_info["middleware_found"]:
                                route_info["middleware_found"].append(middleware_part)
                        except:
                            pass
                    
                    # Controllers
                    if 'Controller@' in line or 'Controller::class' in line:
                        try:
                            if 'Controller@' in line:
                                controller = line.split('Controller@')[0].split()[-1] + 'Controller'
                            else:
                                controller = line.split('Controller::class')[0].split()[-1] + 'Controller'
                            
                            if controller not in route_info["controllers_found"]:
                                route_info["controllers_found"].append(controller)
                        except:
                            pass
                    
                    # Route names
                    if '->name(' in line:
                        try:
                            name_part = line.split('->name(')[1].split(')')[0]
                            name_part = name_part.replace("'", "").replace('"', '')
                            if name_part not in route_info["route_names"]:
                                route_info["route_names"].append(name_part)
                        except:
                            pass
                
                detailed_routes.append({
                    "path": route_file['path'],
                    "url": full_url,
                    "status": response.status_code,
                    "route_analysis": route_info
                })
        
        return detailed_routes if detailed_routes else None
        
    except Exception:
        pass
    
    return None


def batch_scan(urls: List[str]) -> List[Dict[str, Union[str, List, None]]]:
    """
    Scan multiple URLs for route file exposure.
    
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