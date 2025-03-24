from fastapi import FastAPI, Query, HTTPException
import requests
from bs4 import BeautifulSoup
import ssl
import socket
import logging

app = FastAPI()

# Home route
@app.get("/")
def read_root():
    return {"message":"Web Security Scanner is running!"}
logging.basicConfig(level=logging.INFO)

@app.get("/ping")
def ping_website(url: str):
    try:
        response = requests.get(url, timeout=10)
        logging.info(f"Checked {url}, Status: {response.status_code}")
        return {"message": f"Website {url} is reachable."}
    except requests.exceptions.RequestException as e:
        logging.error(f"Error accessing {url}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error accessing {url}: {str(e)}")
    # """Check if a website is reachable."""
    # try:
    #     response = requests.get(url, timeout=10)
    #     response.raise_for_status()  # Raise an exception for HTTP errors (4xx/5xx)
    #     return {"message": f"Website {url} is reachable."}
    # except requests.exceptions.RequestException as e:
    #     raise HTTPException(status_code=500, detail=f"Error accessing {url}: {str(e)}")
    #     if response.status_code == 200:
    #         return {"message": f"Website {url} is reachable."}
    #     else:
    #         return {"message": f"Website {url} returned status code {response.status_code}."}
    # except requests.exceptions.RequestException as e:
    #     return {"message": f"Error accessing {url}: {str(e)}"}
@app.get("/scan", summary="Scan a website for security headers", description="Checks the presence of security headers like X-Content-Type-Options, Strict-Transport-Security, etc.")
def scan_website(url: str):
    """Scan the website for common security headers."""
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        security_headers = {
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "X-XSS-Protection": headers.get("X-XSS-Protection"),
            "Referrer-Policy": headers.get("Referrer-Policy")
        }
        return {"url": url, "security_headers": security_headers}
    except requests.exceptions.RequestException as e:
        return {"message": f"Error accessing {url}: {str(e)}"}
@app.get("/ssl_check")
def ssl_check(url: str):
    """Check if the website uses SSL/TLS."""
    try:
        host = url.replace("https://", "").replace("http://", "")
        cert = ssl.get_server_certificate((host, 443))
        return {"message": f"SSL Certificate found for {url}!"}
    except Exception as e:
        return {"message": f"SSL/TLS error for {url}: {str(e)}"}
        
def home():
    return {"message": "Web Security Scanner API is running!"}

# URL validation function
def validate_url(url):
    try:
        response = requests.get(url)
        return response.status_code == 200
    except:
        return False

# Security headers check
def check_headers(url):
    response = requests.get(url)
    headers = response.headers
    required_headers = [
        "X-Frame-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options"
    ]
    missing_headers = [h for h in required_headers if h not in headers]
    return missing_headers

# SQL Injection test
sqli_payloads = ["' OR '1'='1", "'; DROP TABLE users; --"]

def test_sql_injection(url):
    for payload in sqli_payloads:
        target_url = f"{url}?id={payload}"
        response = requests.get(target_url)
        if "syntax error" in response.text.lower() or "mysql" in response.text.lower():
            return True
    return False

# XSS Detection
xss_payloads = ['<script>alert("XSS")</script>', '"><img src=x onerror=alert("XSS")>']

def test_xss(url):
    for payload in xss_payloads:
        target_url = f"{url}?q={payload}"
        response = requests.get(target_url)
        if payload in response.text:
            return True
    return False

# Scanner Endpoint
@app.get("/scan/")
def scan_website(url: str = Query(..., title="Website URL")):
    if not validate_url(url):
        return {"error": "Invalid URL"}

    headers_result = check_headers(url)
    sqli_result = test_sql_injection(url)
    xss_result = test_xss(url)

    return {
        "url": url,
        "missing_headers": headers_result,
        "sql_injection_vulnerable": sqli_result,
        "xss_vulnerable": xss_result
    }

