from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import scan_engine

app = FastAPI(title="Scan Engine API")

# Request model for port scan
class PortScanRequest(BaseModel):
    target: str
    ports: Optional[List[int]] = None
    
# Request model for HTTP header scan
class HTTPHeaderRequest(BaseModel):
    url: str

@app.post("/scan/port")
def scan_ports(request: PortScanRequest):
    """
    Initiates port scan for the given ports
    Defaults to scanning 22, 80, 443 if no ports are provided
    """
    ports_to_scan = request.ports if request.ports else [22, 80, 443]
    results = scan_engine.scan_ports(request.target, ports_to_scan)
    return {"target": request.target, "ports": results}

@app.post("/scan/http-header")
def scan_http_header(request: HTTPHeaderRequest):
    """
    Performs HTTP header scan for the given URL
    Retruns the http headers and status code
    """
    results = scan_engine.analyze_http_header(request.url)
    if "error" in results:
        raise HTTPException(status_code=500, detail=results["error"])
    return results

@app.post("/scan/full")
def full_scan(target: str, url: str):
    """
    Performs a comprehensive scan of the target
    Includes port scan, HTTP header scan, and vulnerability scan
    """
    port_results = scan_engine.scan_ports(target, [22, 80, 443])
    http_results = scan_engine.analyze_http_header(url)
    return {
        "target": target,
        "url": url,
        "ports": port_results,
        "http_header": http_results
    }
