from collections import Counter
from typing import Dict, Generator
import re
import csv

# Log file path
file_path = r"sample.log"  # Using raw string to handle escape characters in the path
output_file = "log_analysis_results.csv"  # CSV output file


# Parse log file line by line (generator function)
def log_file_parser(file_path: str) -> Generator[str, None, None]:
    with open(file_path, 'r') as file:
        for line in file:
            yield line  # Yields each line one by one


# 1.Extract IP addresses from log lines (generator function)
def ip_extract(log_lines: Generator[str, None, None]) -> Generator[str, None, None]:
    ip_search = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')  # IPv4 addresses
    for line in log_lines:
        ip_found = ip_search.search(line)
        if ip_found:
            yield ip_found.group(0)  # Yield the found IP address

# Count requests per IP address and return a dictionary of counts
def ip_request_counter(file_path: str) -> Dict[str, int]:
    log_lines = log_file_parser(file_path)  
    ip_addresses = ip_extract(log_lines)  
    return dict(Counter(ip_addresses).most_common())  


# 2. Identify the Most Frequently Accessed Endpoint:
def endpoint_extract(log_lines: Generator[str,None,None]) -> Generator[str,None,None]:
    endpoint_search = re.compile(r'\"(?:GET|POST|PUT|DELETE)\s([^\s]+)\sHTTP')  
    for line in log_lines:
        endpoint_found = endpoint_search.search(line)
        if endpoint_found:
            yield endpoint_found.group(1)  

def endpoint_count(file_path : str) -> str:
    log_lines = log_file_parser(file_path)  
    endpoints = endpoint_extract(log_lines) 
    endpoint_counts = Counter(endpoints)  
    most_common = endpoint_counts.most_common(1)  
    if most_common:
        return most_common[0]  # Returns the most frequent endpoint and its count   
    return None  


# 3. Detect Suspicious Activity

# Extract failed login attempts (401 status or specific failure messages)
def failed_login_attempts(log_lines: Generator[str, None, None]) -> Generator[str, None, None]:
    failed_login_search = re.compile(r'401\s.*(?:Invalid credentials|unauthorized)', re.IGNORECASE)
    for line in log_lines:
        if failed_login_search.search(line):
            ip_search = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            ip_found = ip_search.search(line)
            if ip_found:
                yield ip_found.group(0)  

def failed_log_counter(file_path: str, threshold: int = 10) -> Dict[str, int]:
    log_lines = log_file_parser(file_path)
    failed_ips = failed_login_attempts(log_lines)
    ip_counts = Counter(failed_ips)
    suspicious_ips = {ip: count for ip, count in ip_counts.items() if count > threshold}
    return suspicious_ips


#function to save analysis in csv file
def save_to_csv(ip_counts: Dict[str, int], most_accessed_endpoint: tuple, suspicious_ips: Dict[str, int]) -> None:
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        
        writer.writerow([])  
        
        # Write Most Accessed Endpoints
        writer.writerow(["Endpoint", "Access Count"])
        if most_accessed_endpoint:
            endpoint, count = most_accessed_endpoint
            writer.writerow([endpoint, count])
        else:
            writer.writerow(["No endpoints found", "0"])
        
        writer.writerow([])
        # Write Suspicious Activity (Failed Login Attempts)
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])


# Main function to process the log file and display IP counts
def main(file_path: str,  threshold: int = 10) -> None:
    ip_counts = ip_request_counter(file_path)
    print(f"{'IP Address':<20} {'Request Count'}")
    print("="*40)  
    for ip, count in ip_counts.items():
        print(f"{ip:<20} {count}")  

    frequently_accessed_endpoint = endpoint_count(file_path)
    if frequently_accessed_endpoint:
        endpoint, count = frequently_accessed_endpoint
        print("\nMost Frequently Accessed Endpoint:")
        print(f"{endpoint} (Accessed {count} times)")
    else:
        print("\nNo endpoints found.")

    suspicious_ips = failed_log_counter(file_path, threshold)  # Get suspicious IPs
    if suspicious_ips:
        print(f"\nSuspicious Activity Detected (IPs with failed login attempts > {threshold}):")
        print(f"{'IP Address':<20} {'Failed Login Count'}")
        print("="*40)
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("\nNo suspicious activity detected.")

    save_to_csv(ip_counts, frequently_accessed_endpoint, suspicious_ips)
    print(f"\nResults saved to {output_file}")


if __name__ == "__main__":
    import sys
    main(sys.argv[1])
