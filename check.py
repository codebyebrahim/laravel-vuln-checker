import argparse
import time
from datetime import datetime
from colorama import Fore, Back, Style, init

init(autoreset=True)

from modules.detect_laravel import is_laravel
from modules.env_exposure import scan as scan_env
from modules.cve_2021_3129 import scan as scan_ignition
from modules.cve_2024_52301 import scan as scan_env_inject
from modules.cve_2024_29291 import scan as scan_debug_exposure
from modules.sqli_time_api import scan as scan_sqli_time
from modules.git_exposure import scan as scan_git_exposure
from modules.log_exposure import scan as scan_log_exposure
from modules.env_backup_exposure import scan as scan_env_backup
from modules.phpinfo_exposure import scan as scan_phpinfo
from modules.debug_tools_exposure import scan as scan_debugtools
from modules.routes_exposure import scan as scan_routes
from modules.token_leakage import scan as scan_tokens
from modules.deserialization_poi import scan as scan_poi
from modules.laravel_filemanager_exposure import scan_detailed
from modules.queue_deserialization_rce import scan_detailed as scan_queue_deserialization
from modules.mass_assignment_checker import scan as scan_mass_assignment

def show_banner():
    print(f"""
{Fore.CYAN}{Style.BRIGHT}══════════════════════════════════════════════════════════════════════
                                                                                             
    {Fore.RED}██╗      █████╗ ██████╗  █████╗ ██╗   ██╗███████╗██╗                           
    {Fore.RED}██║     ██╔══██╗██╔══██╗██╔══██╗██║   ██║██╔════╝██║                           
    {Fore.RED}██║     ███████║██████╔╝███████║██║   ██║█████╗  ██║                           
    {Fore.RED}██║     ██╔══██║██╔══██╗██╔══██║╚██╗ ██╔╝██╔══╝  ██║                           
    {Fore.RED}███████╗██║  ██║██║  ██║██║  ██║ ╚████╔╝ ███████╗███████╗                      
    {Fore.RED}╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚══════╝                      
                                                                                             
              {Fore.YELLOW} VULNERABILITY SCANNER                           	      
                                                                                             
         {Fore.GREEN} Developed by: Ebrahim                                                
         {Fore.BLUE} GitHub: github.com/codebyebrahim                                      
         {Fore.MAGENTA} Scan Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}          
                                                                                             
    {Fore.WHITE}         Laravel Security Assessment Tool                               
                                                                                             
{Fore.CYAN}══════════════════════════════════════════════════════════════════════{Style.RESET_ALL}
    """)

def print_separator():
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")

def print_status(message, status_type="info"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    if status_type == "info":
        print(f"{Fore.CYAN}[{timestamp}] {Fore.BLUE}[•] {Fore.WHITE}{message}{Style.RESET_ALL}")
    elif status_type == "success":
        print(f"{Fore.CYAN}[{timestamp}] {Fore.GREEN}[•] {Fore.WHITE}{message}{Style.RESET_ALL}")
    elif status_type == "warning":
        print(f"{Fore.CYAN}[{timestamp}] {Fore.YELLOW}[!] {Fore.WHITE}{message}{Style.RESET_ALL}")
    elif status_type == "critical":
        print(f"{Fore.CYAN}[{timestamp}] {Fore.RED}[CRITICAL] {Fore.WHITE}{message}{Style.RESET_ALL}")
    elif status_type == "high":
        print(f"{Fore.CYAN}[{timestamp}] {Fore.MAGENTA}[HIGH] {Fore.WHITE}{message}{Style.RESET_ALL}")
    elif status_type == "error":
        print(f"{Fore.CYAN}[{timestamp}] {Fore.RED}[✗] {Fore.WHITE}{message}{Style.RESET_ALL}")

def print_vulnerability_details(title, details, indent="  "):
    print(f"{indent}{Fore.YELLOW}📍 {title}:{Style.RESET_ALL}")
    for key, value in details.items():
        if key == "variables" and isinstance(value, list):
            value = ', '.join(value)
        elif key == "detected_strings" and isinstance(value, list):
            value = ', '.join(value)
        print(f"{indent}  {Fore.CYAN}{key.replace('_', ' ').title()}:{Style.RESET_ALL} {Fore.WHITE}{value}{Style.RESET_ALL}")

def main():
    show_banner()
    print_separator()

    parser = argparse.ArgumentParser(description="Laravel Vulnerability Scanner")
    parser.add_argument("url", nargs="?", help="Target URL (e.g., https://example.com)")
    args = parser.parse_args()

    if not args.url:
        print(f"{Fore.YELLOW}[?] Enter target URL: {Style.RESET_ALL}", end="")
        args.url = input().strip()

    target_url = args.url.strip().rstrip("/")

    print_status(f"Initializing scan for: {Fore.YELLOW}{target_url}{Style.RESET_ALL}", "info")
    print_status("Checking if target is a Laravel application...", "info")
    
    if not is_laravel(target_url):
        print_status("This target does NOT appear to be a Laravel application.", "error")
        print_status("Exiting scanner...", "error")
        return
    else:
        print_status("Laravel framework detected! ", "success")
        print_status("Starting comprehensive vulnerability assessment...", "info")
        print_separator()

    print_status("Scanning for .env file exposure...", "info")
    env_result = scan_env(target_url)
    if env_result:
        print_status(".env File Exposed", "critical")
        print_vulnerability_details("Environment File Details", {
            "path": env_result['path'],
            "url": env_result['url'],
            "found_variables": env_result['variables'],
            "size": f"{env_result['size']} bytes"
        })
    else:
        print_status(".env file is secure", "success")
    print()


    print_status("Testing for Ignition RCE (CVE-2021-3129)...", "info")
    ignition_result = scan_ignition(target_url)
    if ignition_result:
        print_status("Ignition RCE Vulnerability Detected (CVE-2021-3129)", "critical")
        print_vulnerability_details("Ignition RCE Details", {
            "path": ignition_result['path'],
            "url": ignition_result['url'],
            "http_status": ignition_result['http_status']
        })
    else:
        print_status("Ignition RCE vulnerability not detected", "success")
    print()


    print_status("Testing for Environment Session Injection (CVE-2024-52301)...", "info")
    env_inject_result = scan_env_inject(target_url)
    if env_inject_result:
        print_status("Environment Manipulation Detected (CVE-2024-52301)", "critical")
        print_vulnerability_details("Environment Injection Details", {
            "path": env_inject_result['path'],
            "url": env_inject_result['url'],
            "http_status": env_inject_result['http_status']
        })
    else:
        print_status("Environment session injection not detected", "success")
    print()


    print_status("Scanning for Debug Information Exposure (CVE-2024-29291)...", "info")
    debug_result = scan_debug_exposure(target_url)
    if debug_result:
        print_status("Laravel Debug Info Exposed (CVE-2024-29291)", "critical")
        print_vulnerability_details("Debug Exposure Details", {
            "path": debug_result['path'],
            "url": debug_result['url'],
            "http_status": debug_result['http_status']
        })
    else:
        print_status("No debug information exposure detected", "success")
    print()


    print_status("Testing for Time-Based SQL Injection...", "info")
    sqli_result = scan_sqli_time(target_url)
    if sqli_result:
        print_status("Time-Based SQL Injection Detected", "high")
        print_vulnerability_details("SQL Injection Details", {
            "path": sqli_result['path'],
            "url": sqli_result['url'],
            "delay": f"{sqli_result['delay']:.2f} seconds"
        })
    else:
        print_status("No SQL injection vulnerability detected", "success")
    print()


    print_status("Scanning for Git directory exposure...", "info")
    git_result = scan_git_exposure(target_url)
    if git_result:
        print_status("Git Directory Exposed", "critical")
        print_vulnerability_details("Git Exposure Details", {
            "path": git_result['path'],
            "url": git_result['url'],
            "http_status": git_result['http_status']
        })
    else:
        print_status(".git directory is secure", "success")
    print()


    print_status("Checking for Laravel log file exposure...", "info")
    log_result = scan_log_exposure(target_url)
    if log_result:
        print_status("Laravel Log File Exposed", "critical")
        print_vulnerability_details("Log File Details", {
            "path": log_result['path'],
            "url": log_result['url'],
            "http_status": log_result['http_status']
        })
    else:
        print_status("Laravel log files are secure", "success")
    print()


    print_status("Scanning for environment backup files...", "info")
    env_backup_result = scan_env_backup(target_url)
    if env_backup_result:
        print_status("Environment Backup File Exposed", "critical")
        print_vulnerability_details("Backup File Details", {
            "path": env_backup_result['path'],
            "url": env_backup_result['url'],
            "http_status": env_backup_result['http_status']
        })
    else:
        print_status("No exposed environment backup files found", "success")
    print()


    print_status("Testing for PHPinfo exposure...", "info")
    phpinfo_result = scan_phpinfo(target_url)
    if phpinfo_result:
        print_status("Exposed PHPinfo File Detected", "critical")
        print_vulnerability_details("PHPinfo Details", {
            "path": phpinfo_result['path'],
            "url": phpinfo_result['url'],
            "http_status": phpinfo_result['http_status']
        })
    else:
        print_status("No exposed phpinfo files found", "success")
    print()


    print_status("Scanning for debug/admin tools exposure...", "info")
    debugtools_result = scan_debugtools(target_url)
    if debugtools_result:
        print_status("Public Laravel Debug/Admin Tools Found", "critical")
        for i, tool in enumerate(debugtools_result, 1):
            print_vulnerability_details(f"Tool #{i}", {
                "tool": tool['tool'],
                "path": tool['path'],
                "url": tool['url'],
                "http_status": tool['status']
            })
    else:
        print_status("No public debug/admin tools found", "success")
    print()


    print_status("Checking for Laravel route file exposure...", "info")
    routes_result = scan_routes(target_url)
    if routes_result:
        print_status("Public Laravel Route Files Detected", "critical")
        for i, r in enumerate(routes_result, 1):
            print_vulnerability_details(f"Route File #{i}", {
                "path": r['path'],
                "url": r['url'],
                "http_status": r['status']
            })
    else:
        print_status("No exposed Laravel route files found", "success")
    print()


    print_status("Testing for Laravel token leakage...", "info")
    token_result = scan_tokens(target_url)
    if token_result and token_result.get("cookies"):
        print_status("Laravel Token Leakage Detected", "critical")
        print_vulnerability_details("Token Details", {"url": token_result['url']})
        for i, cookie in enumerate(token_result["cookies"], 1):
            print(f"    {Fore.YELLOW}Cookie #{i}:{Style.RESET_ALL}")
            print(f"      {Fore.CYAN}Name:{Style.RESET_ALL} {cookie['name']}")
            print(f"      {Fore.CYAN}Secure:{Style.RESET_ALL} {cookie.get('secure')}")
            print(f"      {Fore.CYAN}HttpOnly:{Style.RESET_ALL} {cookie.get('httponly')}")
            print(f"      {Fore.CYAN}SameSite:{Style.RESET_ALL} {cookie.get('samesite')}")
    else:
        print_status("No Laravel token leakage detected", "success")
    print()


    print_status("Scanning for Laravel File Manager exposure...", "info")
    lfm_result = scan_detailed(target_url)
    if lfm_result:
        print_status("Laravel File Manager Exposure Detected", "critical")
        print_vulnerability_details("File Manager Details", {
            "path": lfm_result['path'],
            "url": lfm_result['url'],
            "http_status": lfm_result['http_status'],
            "detected_keywords": lfm_result['detected_strings'],
            "content_size": f"{lfm_result['content_size']} bytes"
        })

        if lfm_result.get("analysis"):
            print(f"    {Fore.YELLOW} Security Analysis:{Style.RESET_ALL}")
            for concern in lfm_result["analysis"].get("security_concerns", []):
                print(f"      {Fore.RED}[!]{Style.RESET_ALL} {concern}")
            if lfm_result["analysis"].get("framework_indicators"):
                frameworks = ', '.join(lfm_result['analysis']['framework_indicators'])
                print(f"      {Fore.GREEN}[+]{Style.RESET_ALL} Frameworks Detected: {frameworks}")
    else:
        print_status("Laravel File Manager is secure", "success")
    print()


    print_status("Testing for Laravel Queue Deserialization RCE (CVE-2022-21824)...", "info")
    queue_rce_result = scan_queue_deserialization(target_url)
    if queue_rce_result:
        print_status("Laravel Queue Deserialization RCE Analysis (CVE-2022-21824)", "critical")
        print_vulnerability_details("Queue RCE Analysis", {
            "target": queue_rce_result['target_url'],
            "total_vulnerabilities": queue_rce_result['total_vulnerabilities'],
            "accessible_endpoints": queue_rce_result['total_accessible'],
            "risk_level": queue_rce_result['risk_assessment']['risk_level'],
            "risk_score": queue_rce_result['risk_assessment']['risk_score']
        })
        
        if queue_rce_result['risk_assessment']['recommendations']:
            print(f"    {Fore.YELLOW}• Recommendations:{Style.RESET_ALL}")
            for rec in queue_rce_result['risk_assessment']['recommendations']:
                print(f"      {Fore.CYAN}•{Style.RESET_ALL} {rec}")
    else:
        print_status("No Laravel Queue RCE vulnerabilities detected", "success")
    print()


    print_status("Testing for Mass Assignment vulnerabilities...", "info")
    mass_assignment_result = scan_mass_assignment(target_url)
    if mass_assignment_result:
        print_status("Potential Mass Assignment Vulnerabilities Detected", "critical")
        for result in mass_assignment_result:
            print_vulnerability_details("Mass Assignment Details", {
                "path": result['endpoint'],
                "url": result['url'],
                "payload_used": result['payload'],
                "http_status": result['status_code'],
                "response_snippet": f"{result['response_snippet'][:150]}..."
        })
    else:
        print_status("No mass assignment vulnerability detected", "success")


    print_status("Testing for PHP Object Injection vulnerabilities...", "info")
    poi_result = scan_poi(target_url)
    if poi_result:
        print_status("PHP Object Injection Detected!", "critical")
        print_vulnerability_details("Object Injection Details", {
            "url": poi_result['url'],
            "method": poi_result['method'],
            "payload": poi_result['payload'],
            "http_status": poi_result['status_code'],
            "response_snippet": poi_result['response_snippet']
        })
    else:
        print_status("No PHP Object Injection vulnerabilities found", "success")
    print()


    print_separator()
    print_status("Vulnerability assessment completed!", "success")
    print_status(f"Scan finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "info")
    print(f"""
{Fore.CYAN}{Style.BRIGHT}══════════════════════════════════════════════════════════════════════
                                                                     
     {Fore.GREEN} Laravel Security Assessment Complete                         
                                                                     
     {Fore.YELLOW} For more tools and updates:                                  
     {Fore.BLUE} github.com/codebyebrahim                                 
                                                                     
     {Fore.MAGENTA} Report bugs or suggestions via GitHub Issues              
                                                                     
     {Fore.RED} Remember: Use this tool only on systems you own or        
        have explicit permission to test!                           
                                                                    
{Fore.CYAN}══════════════════════════════════════════════════════════════════════{Style.RESET_ALL}
    """)

if __name__ == "__main__":
    main()
