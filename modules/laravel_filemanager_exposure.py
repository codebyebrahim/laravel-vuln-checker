#!/usr/bin/env python3
"""
Laravel File Manager Exposure Scanner

This module detects whether the Laravel File Manager (typically UniSharp/laravel-filemanager)
is publicly accessible without proper authentication. This can lead to unauthorized file
access, upload capabilities, and potential security vulnerabilities.
"""

import requests
from typing import Dict, List, Optional, Union


def scan(url: str) -> Optional[Dict[str, Union[str, int]]]:
    """
    Scan for exposed Laravel File Manager installations.
    
    Args:
        url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Dictionary with exposure details if found, None otherwise
        Format: {
            "path": "/laravel-filemanager",
            "url": "https://example.com/laravel-filemanager", 
            "http_status": 200,
            "detected_string": "filemanager"
        }
    """
    if not url:
        return None
    
    try:
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        url = url.rstrip('/')
        
        # Laravel File Manager paths to test
        filemanager_paths = [
            '/laravel-filemanager',
            '/filemanager',
            '/admin/laravel-filemanager',
            '/admin/filemanager',
            '/admin/file-manager'
        ]
        
        # Detection keywords (case-insensitive)
        detection_keywords = [
            'filemanager',
            'upload',
            'files',
            'images',
            'unisharp',
            'lfm'
        ]
        
        for path in filemanager_paths:
            full_url = url + path
            
            try:
                # Send GET request with timeout
                response = requests.get(
                    full_url,
                    timeout=10,
                    allow_redirects=True
                )
                
                # Check if status is 200 and content contains keywords
                if response.status_code == 200:
                    content = response.text.lower()
                    
                    # Check for detection keywords
                    for keyword in detection_keywords:
                        if keyword in content:
                            return {
                                "path": path,
                                "url": full_url,
                                "http_status": response.status_code,
                                "detected_string": keyword
                            }
            
            except requests.RequestException:
                # Continue to next path if request fails
                continue
        
    except Exception:
        # Silently handle all other exceptions
        pass
    
    return None


def scan_detailed(url: str) -> Optional[Dict[str, Union[str, int, List, Dict]]]:
    """
    Perform detailed scan with comprehensive analysis of Laravel File Manager exposure.
    
    Args:
        url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Detailed exposure information
    """
    if not url:
        return None
    
    try:
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        url = url.rstrip('/')
        
        # Extended paths including common variations
        extended_paths = [
            '/laravel-filemanager',
            '/filemanager',
            '/admin/laravel-filemanager',
            '/admin/filemanager',
            '/admin/file-manager',
            '/lfm',
            '/file-manager',
            '/files',
            '/uploads',
            '/media',
            '/assets/filemanager',
            '/public/laravel-filemanager',
            '/backend/filemanager'
        ]
        
        # Extended detection keywords
        extended_keywords = [
            'filemanager',
            'upload',
            'files',
            'images',
            'unisharp',
            'lfm',
            'laravel file manager',
            'file browser',
            'media manager',
            'asset manager',
            'tinymce',
            'ckeditor',
            'browse files'
        ]
        
        for path in extended_paths:
            full_url = url + path
            
            try:
                response = requests.get(
                    full_url,
                    timeout=10,
                    allow_redirects=True
                )
                
                if response.status_code == 200:
                    content = response.text.lower()
                    found_keywords = []
                    
                    # Find all matching keywords
                    for keyword in extended_keywords:
                        if keyword in content:
                            found_keywords.append(keyword)
                    
                    if found_keywords:
                        # Analyze the response for additional details
                        analysis = _analyze_filemanager_response(response)
                        
                        return {
                            "path": path,
                            "url": full_url,
                            "http_status": response.status_code,
                            "detected_strings": found_keywords,
                            "primary_detected_string": found_keywords[0],
                            "content_size": len(response.content),
                            "analysis": analysis,
                            "response_headers": dict(response.headers)
                        }
            
            except requests.RequestException:
                continue
        
    except Exception:
        pass
    
    return None


def _analyze_filemanager_response(response: requests.Response) -> Dict[str, Union[bool, List[str]]]:
    """
    Analyze file manager response for additional security information.
    
    Args:
        response: HTTP response object
        
    Returns:
        Dict: Analysis results
    """
    analysis = {
        "has_authentication": False,
        "allows_upload": False,
        "shows_file_listing": False,
        "framework_indicators": [],
        "security_concerns": []
    }
    
    try:
        content = response.text.lower()
        
        # Check for authentication indicators
        auth_indicators = [
            'login',
            'password',
            'authenticate',
            'csrf',
            'token',
            'signin',
            'unauthorized'
        ]
        
        if any(indicator in content for indicator in auth_indicators):
            analysis["has_authentication"] = True
        else:
            analysis["security_concerns"].append("No authentication detected")
        
        # Check for upload capabilities
        upload_indicators = [
            'upload',
            'file upload',
            'drag',
            'drop files',
            'choose file',
            'select files'
        ]
        
        if any(indicator in content for indicator in upload_indicators):
            analysis["allows_upload"] = True
            if not analysis["has_authentication"]:
                analysis["security_concerns"].append("Upload functionality without authentication")
        
        # Check for file listing
        listing_indicators = [
            'file list',
            'directory',
            'folder',
            'tree view',
            'file browser',
            'files and folders'
        ]
        
        if any(indicator in content for indicator in listing_indicators):
            analysis["shows_file_listing"] = True
            if not analysis["has_authentication"]:
                analysis["security_concerns"].append("File listing accessible without authentication")
        
        # Framework indicators
        framework_indicators = [
            ('laravel', 'Laravel Framework'),
            ('unisharp', 'UniSharp Laravel File Manager'),
            ('tinymce', 'TinyMCE Integration'),
            ('ckeditor', 'CKEditor Integration'),
            ('bootstrap', 'Bootstrap UI Framework'),
            ('jquery', 'jQuery Library')
        ]
        
        for indicator, description in framework_indicators:
            if indicator in content:
                analysis["framework_indicators"].append(description)
        
    except Exception:
        pass
    
    return analysis


def scan_with_authentication_test(url: str) -> Optional[Dict[str, Union[str, int, bool]]]:
    """
    Scan for file manager and test if it requires authentication.
    
    Args:
        url (str): The target URL to scan
        
    Returns:
        Optional[Dict]: Exposure information with authentication status
    """
    if not url:
        return None
    
    try:
        # First run basic scan
        basic_result = scan(url)
        if not basic_result:
            return None
        
        # Test if the exposed file manager requires authentication
        filemanager_url = basic_result["url"]
        
        # Make request without authentication
        response = requests.get(
            filemanager_url,
            timeout=10,
            allow_redirects=False  # Don't follow redirects to login pages
        )
        
        # Analyze response for authentication requirements
        requires_auth = False
        auth_indicators = []
        
        if response.status_code in [401, 403]:
            requires_auth = True
            auth_indicators.append("HTTP authentication required")
        elif response.status_code in [302, 301]:
            # Check if redirect goes to login page
            location = response.headers.get('Location', '').lower()
            if any(auth_term in location for auth_term in ['login', 'signin', 'auth']):
                requires_auth = True
                auth_indicators.append("Redirects to login page")
        elif response.status_code == 200:
            content = response.text.lower()
            
            # Check if page shows login form or authentication required
            if any(term in content for term in ['login', 'password', 'sign in', 'authenticate']):
                requires_auth = True
                auth_indicators.append("Login form present")
            
            # If no auth indicators and file manager functions are accessible
            if not requires_auth and any(term in content for term in ['upload', 'files', 'browse', 'directory']):
                auth_indicators.append("Publicly accessible without authentication")
        
        return {
            "path": basic_result["path"],
            "url": filemanager_url,
            "http_status": response.status_code,
            "detected_string": basic_result["detected_string"],
            "requires_authentication": requires_auth,
            "authentication_indicators": auth_indicators,
            "publicly_accessible": not requires_auth
        }
        
    except Exception:
        pass
    
    return None


def scan_multiple_variants(url: str) -> Optional[List[Dict[str, Union[str, int]]]]:
    """
    Scan for multiple file manager variants and installations.
    
    Args:
        url (str): The target URL to scan
        
    Returns:
        Optional[List[Dict]]: List of all found file manager installations
    """
    if not url:
        return None
    
    try:
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        url = url.rstrip('/')
        
        found_installations = []
        
        # Comprehensive list of file manager paths
        all_paths = [
            '/laravel-filemanager',
            '/filemanager',
            '/admin/laravel-filemanager',
            '/admin/filemanager',
            '/admin/file-manager',
            '/lfm',
            '/file-manager',
            '/files',
            '/uploads',
            '/media',
            '/assets/filemanager',
            '/public/laravel-filemanager',
            '/backend/filemanager',
            '/cms/filemanager',
            '/panel/filemanager',
            '/dashboard/filemanager'
        ]
        
        detection_keywords = [
            'filemanager', 'upload', 'files', 'images', 'unisharp', 'lfm',
            'laravel file manager', 'file browser', 'media manager'
        ]
        
        for path in all_paths:
            full_url = url + path
            
            try:
                response = requests.get(
                    full_url,
                    timeout=5,  # Shorter timeout for multiple requests
                    allow_redirects=True
                )
                
                if response.status_code == 200:
                    content = response.text.lower()
                    
                    for keyword in detection_keywords:
                        if keyword in content:
                            found_installations.append({
                                "path": path,
                                "url": full_url,
                                "http_status": response.status_code,
                                "detected_string": keyword
                            })
                            break  # Found one, move to next path
            
            except requests.RequestException:
                continue
        
        return found_installations if found_installations else None
        
    except Exception:
        pass
    
    return None


def batch_scan(urls: List[str]) -> List[Dict[str, Union[str, Dict, None]]]:
    """
    Scan multiple URLs for Laravel File Manager exposure.
    
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