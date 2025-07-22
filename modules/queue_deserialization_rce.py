#!/usr/bin/env python3
"""
Laravel Queue Deserialization RCE Scanner (CVE-2022-21824)

This module detects potential Laravel deserialization attack surfaces by testing
queue-related endpoints for public accessibility and vulnerable serialized content.
CVE-2022-21824 involves Laravel's queue system being susceptible to deserialization
attacks when queue endpoints are misconfigured or publicly accessible.
"""

import requests
import re
from typing import Dict, List, Optional, Union


def scan(url: str) -> Optional[Dict[str, Union[str, int]]]:
    """
    Scan for Laravel queue deserialization vulnerabilities (CVE-2022-21824).
    
    Args:
        url (str): The base URL to scan
        
    Returns:
        Optional[Dict]: Dictionary with vulnerability details if found, None if safe
        Format: {
            "endpoint": "/queue/worker",
            "url": "https://example.com/queue/worker",
            "status_code": 200,
            "vulnerability_type": "exposed_queue_endpoint",
            "content_excerpt": "O:8:\"Job\":..."
        }
    """
    if not url:
        return None
    
    try:
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        url = url.rstrip('/')
        
        # Queue-related endpoints to test
        queue_endpoints = [
            '/queue',
            '/queue/listen',
            '/queue/worker',
            '/queue/work',
            '/queue/failed',
            '/queue/retry',
            '/queue/restart',
            '/queue/status',
            '/api/queue',
            '/admin/queue',
            '/horizon/api/jobs',
            '/horizon/api/workload'
        ]
        
        for endpoint in queue_endpoints:
            full_url = url + endpoint
            
            try:
                # Send request to queue endpoint
                response = requests.get(
                    full_url,
                    timeout=10,
                    allow_redirects=True
                )
                
                # Check if endpoint is accessible and contains suspicious content
                vulnerability = _analyze_queue_response(response, endpoint, full_url)
                if vulnerability:
                    return vulnerability
                    
            except requests.RequestException:
                # Continue to next endpoint if request fails
                continue
        
        # If no vulnerabilities found, return None (safe)
        return None
        
    except Exception:
        # Silently handle all other exceptions
        return None


def _analyze_queue_response(response: requests.Response, endpoint: str, full_url: str) -> Optional[Dict[str, Union[str, int]]]:
    """
    Analyze queue endpoint response for deserialization vulnerabilities.
    
    Args:
        response: HTTP response object
        endpoint: The endpoint path tested
        full_url: Full URL that was tested
        
    Returns:
        Optional[Dict]: Vulnerability details if found
    """
    try:
        status_code = response.status_code
        content = response.text
        
        # Check if endpoint is accessible (potential misconfiguration)
        if status_code == 200:
            
            # Look for serialized PHP objects in response
            serialized_patterns = [
                r'O:\d+:"[^"]*":\d+:\{',  # PHP object serialization pattern
                r'a:\d+:\{.*\}',          # PHP array serialization
                r's:\d+:"[^"]*"',        # PHP string serialization
                r'i:\d+;',               # PHP integer serialization
            ]
            
            for pattern in serialized_patterns:
                matches = re.findall(pattern, content)
                if matches:
                    # Found serialized content - potential vulnerability
                    excerpt = _extract_content_excerpt(content, matches[0])
                    return {
                        "endpoint": endpoint,
                        "url": full_url,
                        "status_code": status_code,
                        "vulnerability_type": "serialized_content_exposure",
                        "content_excerpt": excerpt,
                        "serialization_pattern": matches[0]
                    }
            
            # Check for Laravel queue-specific indicators
            queue_indicators = [
                'laravel_session',
                'failed_jobs',
                'job_batches',
                'queue:work',
                'queue:listen',
                'horizon',
                'artisan queue',
                'illuminate\\queue',
                'illuminate\\contracts\\queue',
                'queueable'
            ]
            
            content_lower = content.lower()
            for indicator in queue_indicators:
                if indicator in content_lower:
                    # Found queue-related content exposure
                    excerpt = _extract_content_excerpt(content, indicator, case_sensitive=False)
                    return {
                        "endpoint": endpoint,
                        "url": full_url,
                        "status_code": status_code,
                        "vulnerability_type": "exposed_queue_endpoint",
                        "content_excerpt": excerpt,
                        "queue_indicator": indicator
                    }
            
            # Check for JSON responses that might contain serialized data
            if 'application/json' in response.headers.get('content-type', ''):
                json_vulnerabilities = _analyze_json_queue_response(content, endpoint, full_url, status_code)
                if json_vulnerabilities:
                    return json_vulnerabilities
        
        # Check for authentication bypass indicators
        elif status_code in [401, 403]:
            # Queue endpoint exists but is protected (good security)
            return None
        
        elif status_code == 500:
            # Server error might reveal information
            error_indicators = [
                'unserialize',
                'object of class',
                'illuminate\\queue',
                'laravel queue',
                'serialization'
            ]
            
            content_lower = content.lower()
            for indicator in error_indicators:
                if indicator in content_lower:
                    excerpt = _extract_content_excerpt(content, indicator, case_sensitive=False)
                    return {
                        "endpoint": endpoint,
                        "url": full_url,
                        "status_code": status_code,
                        "vulnerability_type": "error_information_disclosure",
                        "content_excerpt": excerpt,
                        "error_indicator": indicator
                    }
        
    except Exception:
        pass
    
    return None


def _analyze_json_queue_response(content: str, endpoint: str, full_url: str, status_code: int) -> Optional[Dict[str, Union[str, int]]]:
    """
    Analyze JSON responses from queue endpoints for vulnerabilities.
    
    Args:
        content: Response content
        endpoint: Endpoint path
        full_url: Full URL
        status_code: HTTP status code
        
    Returns:
        Optional[Dict]: Vulnerability details if found
    """
    try:
        import json
        
        # Try to parse as JSON
        json_data = json.loads(content)
        
        # Look for serialized data within JSON
        def search_serialized_in_json(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    result = search_serialized_in_json(value, current_path)
                    if result:
                        return result
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    current_path = f"{path}[{i}]"
                    result = search_serialized_in_json(item, current_path)
                    if result:
                        return result
            elif isinstance(obj, str):
                # Check if string contains serialized PHP data
                serialized_patterns = [
                    r'O:\d+:"[^"]*":\d+:\{',
                    r'a:\d+:\{.*\}',
                    r's:\d+:"[^"]*"'
                ]
                
                for pattern in serialized_patterns:
                    if re.search(pattern, obj):
                        return {
                            "path": path,
                            "serialized_data": obj[:200] + "..." if len(obj) > 200 else obj,
                            "pattern": pattern
                        }
            
            return None
        
        serialized_result = search_serialized_in_json(json_data)
        if serialized_result:
            return {
                "endpoint": endpoint,
                "url": full_url,
                "status_code": status_code,
                "vulnerability_type": "json_serialized_content",
                "content_excerpt": serialized_result["serialized_data"],
                "json_path": serialized_result["path"]
            }
        
        # Check for queue job data structures
        queue_job_keys = [
            'job', 'payload', 'data', 'command', 'commandName',
            'attempts', 'reserved_at', 'available_at', 'created_at'
        ]
        
        def has_queue_structure(obj):
            if isinstance(obj, dict):
                return len([key for key in queue_job_keys if key in obj]) >= 3
            return False
        
        if has_queue_structure(json_data):
            return {
                "endpoint": endpoint,
                "url": full_url,
                "status_code": status_code,
                "vulnerability_type": "exposed_queue_job_data",
                "content_excerpt": json.dumps(json_data)[:300] + "..."
            }
        
        # Check for arrays that might contain queue data
        if isinstance(json_data, list):
            for item in json_data[:5]:  # Check first 5 items
                if has_queue_structure(item):
                    return {
                        "endpoint": endpoint,
                        "url": full_url,
                        "status_code": status_code,
                        "vulnerability_type": "exposed_queue_job_array",
                        "content_excerpt": json.dumps(item)[:300] + "..."
                    }
        
    except (json.JSONDecodeError, Exception):
        pass
    
    return None


def _extract_content_excerpt(content: str, search_term: str, case_sensitive: bool = True) -> str:
    """
    Extract a content excerpt around the found search term.
    
    Args:
        content: Full response content
        search_term: Term that was found
        case_sensitive: Whether search should be case sensitive
        
    Returns:
        str: Content excerpt around the search term
    """
    try:
        if not case_sensitive:
            search_content = content.lower()
            search_term = search_term.lower()
        else:
            search_content = content
        
        # Find the position of the search term
        pos = search_content.find(search_term)
        if pos == -1:
            # Fallback: return first 200 characters
            return content[:200] + "..." if len(content) > 200 else content
        
        # Extract 100 characters before and after the found term
        start = max(0, pos - 100)
        end = min(len(content), pos + len(search_term) + 100)
        
        excerpt = content[start:end]
        
        # Add ellipsis if we truncated
        if start > 0:
            excerpt = "..." + excerpt
        if end < len(content):
            excerpt = excerpt + "..."
        
        return excerpt
        
    except Exception:
        # Fallback: return first 200 characters
        return content[:200] + "..." if len(content) > 200 else content


def scan_detailed(url: str) -> Optional[Dict[str, Union[str, int, List, Dict]]]:
    """
    Perform detailed scan with comprehensive analysis of queue vulnerabilities.
    
    Args:
        url (str): The base URL to scan
        
    Returns:
        Optional[Dict]: Detailed vulnerability analysis
    """
    if not url:
        return None
    
    try:
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        url = url.rstrip('/')
        
        vulnerabilities = []
        accessible_endpoints = []
        protected_endpoints = []
        
        # Extended list of queue endpoints
        extended_queue_endpoints = [
            '/queue',
            '/queue/listen',
            '/queue/worker',
            '/queue/work',
            '/queue/failed',
            '/queue/retry',
            '/queue/restart',
            '/queue/status',
            '/queue/stats',
            '/api/queue',
            '/api/queue/jobs',
            '/api/queue/failed',
            '/admin/queue',
            '/admin/queue/monitor',
            '/horizon',
            '/horizon/api/jobs',
            '/horizon/api/workload',
            '/horizon/api/masters',
            '/horizon/api/monitoring',
            '/telescope/queue-monitor'
        ]
        
        for endpoint in extended_queue_endpoints:
            full_url = url + endpoint
            
            try:
                response = requests.get(
                    full_url,
                    timeout=5,  # Shorter timeout for detailed scan
                    allow_redirects=True
                )
                
                if response.status_code == 200:
                    accessible_endpoints.append({
                        "endpoint": endpoint,
                        "url": full_url,
                        "content_length": len(response.content)
                    })
                    
                    # Check for vulnerabilities in this endpoint
                    vulnerability = _analyze_queue_response(response, endpoint, full_url)
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
                
                elif response.status_code in [401, 403]:
                    protected_endpoints.append({
                        "endpoint": endpoint,
                        "url": full_url,
                        "status_code": response.status_code
                    })
                
            except requests.RequestException:
                continue
        
        if vulnerabilities or accessible_endpoints:
            return {
                "target_url": url,
                "vulnerabilities": vulnerabilities,
                "accessible_endpoints": accessible_endpoints,
                "protected_endpoints": protected_endpoints,
                "total_vulnerabilities": len(vulnerabilities),
                "total_accessible": len(accessible_endpoints),
                "risk_assessment": _assess_queue_risk(vulnerabilities, accessible_endpoints)
            }
        
    except Exception:
        pass
    
    return None


def _assess_queue_risk(vulnerabilities: List[Dict], accessible_endpoints: List[Dict]) -> Dict[str, Union[str, int]]:
    """
    Assess the risk level based on found vulnerabilities and accessible endpoints.
    
    Args:
        vulnerabilities: List of found vulnerabilities
        accessible_endpoints: List of accessible endpoints
        
    Returns:
        Dict: Risk assessment
    """
    risk_assessment = {
        "risk_level": "low",
        "risk_score": 0,
        "recommendations": []
    }
    
    try:
        # Calculate risk score
        vuln_count = len(vulnerabilities)
        accessible_count = len(accessible_endpoints)
        
        # Base score from vulnerabilities
        if vuln_count > 0:
            risk_assessment["risk_score"] += vuln_count * 30
        
        # Additional score from accessible endpoints
        risk_assessment["risk_score"] += accessible_count * 10
        
        # Check vulnerability types for higher risk
        for vuln in vulnerabilities:
            vuln_type = vuln.get("vulnerability_type", "")
            if "serialized_content" in vuln_type:
                risk_assessment["risk_score"] += 20
            elif "exposed_queue" in vuln_type:
                risk_assessment["risk_score"] += 15
        
        # Determine risk level
        score = risk_assessment["risk_score"]
        if score >= 60:
            risk_assessment["risk_level"] = "critical"
        elif score >= 40:
            risk_assessment["risk_level"] = "high"
        elif score >= 20:
            risk_assessment["risk_level"] = "medium"
        
        # Generate recommendations
        if vuln_count > 0:
            risk_assessment["recommendations"].append("Restrict access to queue endpoints")
            risk_assessment["recommendations"].append("Implement proper authentication for queue management")
        
        if any("serialized" in v.get("vulnerability_type", "") for v in vulnerabilities):
            risk_assessment["recommendations"].append("Review serialized data handling and validation")
            risk_assessment["recommendations"].append("Update Laravel to latest version to address CVE-2022-21824")
        
        if accessible_count > 2:
            risk_assessment["recommendations"].append("Audit queue endpoint exposure and disable unnecessary endpoints")
        
    except Exception:
        pass
    
    return risk_assessment


def batch_scan(urls: List[str]) -> List[Dict[str, Union[str, Dict, None]]]:
    """
    Scan multiple URLs for Laravel queue deserialization vulnerabilities.
    
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