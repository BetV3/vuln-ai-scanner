import socket
import requests

def scan_open_ports(target: str, ports: list) -> list:
    """
    Scan for open ports on the target
    """
    results = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                result = s.connect_ex((target, port))
                if results == 0:
                    results.append({"port": port, "status": "open"})
                else:
                    results.append({"port": port, "status": "closed"})
            except Exception as e:
                results.append({"port": port, "status": "error", "error": str(e)})
    return results
def analyze_http_header(url: str) -> dict:
    """
    Performs HTTP header scan for the given URL
    Returns the HTTP headers and status code
    """
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        missing_headers = []
        # List of security headers to check
        required_headers = [
            "X-Frame-Options",
            "X-XSS-Protection",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Content-Security-Policy",
        ]
        for header in required_headers:
            if header not in headers:
                missing_headers.append(header)
        return {
            "url": url,
            "status_code": response.status_code,
            "headers": headers,
            "missing_headers": missing_headers,
        }
    except Exception as e:
        return {"error": str(e)}
    
if __name__ == "__main__":
    target = "127.0.0.1"
    ports = [22, 80, 443]
    port_results = scan_open_ports(target, ports)
    print("port scan results:", port_results)
    
    url = "http://example.com"
    header_results = analyze_http_header(url)
    print("HTTP header scan results:", header_results)