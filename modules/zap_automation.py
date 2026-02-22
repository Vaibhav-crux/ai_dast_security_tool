import subprocess
import time
import os
import requests
from typing import Dict, Any, Optional
from dotenv import load_dotenv
import logging

load_dotenv()

class ZAPAutomation:
    def __init__(self, port=None, api_key=None, logger=None):
        """Initialize ZAP automation with configuration"""
        # Use port from .env or default to 8080
        self.port = int(port or os.getenv("ZAP_PORT", 8080))
        # Always load API key from environment
        self.api_key = api_key or os.getenv("ZAP_API_KEY", "")
        self.logger = logger or logging.getLogger("ZAPAutomation")
        self.api_url = f"http://127.0.0.1:{self.port}/"

    def _setup_logger(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('ZAPAutomation')
        logger.setLevel(logging.INFO)
        
        # Create console handler
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger

    def _log_request(self, method, url, params=None, data=None):
        self.logger.info(f"ZAP API Request: {method} {url}")
        if params:
            self.logger.info(f"  Params: {params}")
        if data:
            self.logger.info(f"  Data: {data}")

    def _log_response(self, response):
        self.logger.info(f"ZAP API Response: {response.status_code} {response.text[:200]}")

    def _build_url(self, endpoint, params=None):
        url = f"{self.api_url}{endpoint}"
        if params is None:
            params = {}
        if self.api_key:
            params['apikey'] = self.api_key
        if params:
            param_str = '&'.join(f"{k}={v}" for k, v in params.items() if v != "")
            url = f"{url}?{param_str}"
        return url

    def _verify_zap_running(self) -> bool:
        """Verify ZAP is running and accessible"""
        url = self._build_url("JSON/core/view/version/")
        self._log_request("GET", url)
        try:
            response = requests.get(url)
            self._log_response(response)
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Error verifying ZAP: {e}")
            return False

    def start_scan(self, target_url: str) -> Dict[str, Any]:
        """Start a new scan"""
        try:
            # First verify ZAP is running
            if not self._verify_zap_running():
                return {
                    "status": "error",
                    "message": "ZAP is not running. Please start ZAP manually and ensure it's accessible."
                }

            # Start the spider
            spider_params = {"url": target_url, "maxChildren": 0, "recurse": True, "contextName": "", "subtreeOnly": False}
            spider_url = self._build_url("JSON/spider/action/scan/", spider_params)
            self._log_request("POST", spider_url, data=spider_params)
            response = requests.post(spider_url, data=spider_params)
            self._log_response(response)
            spider_id = response.json().get("scan")

            # Wait for spider to complete
            self.logger.info("Waiting for spider to complete...")
            while True:
                status_params = {"scanId": spider_id}
                status_url = self._build_url("JSON/spider/view/status/", status_params)
                self._log_request("GET", status_url)
                response = requests.get(status_url)
                self._log_response(response)
                if response.json().get("status") == "100":
                    break
                time.sleep(5)

            # Start the active scan
            ascan_params = {"url": target_url, "recurse": True, "inScopeOnly": True, "scanPolicyName": "", "method": "", "postData": ""}
            ascan_url = self._build_url("JSON/ascan/action/scan/", ascan_params)
            self._log_request("POST", ascan_url, data=ascan_params)
            response = requests.post(ascan_url, data=ascan_params)
            self._log_response(response)
            ascan_id = response.json().get("scan")

            return {"status": "success", "spider_id": spider_id, "ascan_id": ascan_id, "message": "Scan started successfully"}
        except Exception as e:
            self.logger.error(f"Error starting scan: {str(e)}")
            return {"status": "error", "message": str(e)}

    def get_scan_progress(self, scan_id: str) -> Dict[str, Any]:
        try:
            params = {"scanId": scan_id}
            url = self._build_url("JSON/ascan/view/status/", params)
            self._log_request("GET", url)
            response = requests.get(url)
            self._log_response(response)
            return {"status": "success", "progress": response.json().get("status"), "message": "Progress retrieved successfully"}
        except Exception as e:
            self.logger.error(f"Error getting scan progress: {e}")
            return {"status": "error", "message": str(e)}

    def get_alerts(self, risk_level: Optional[str] = None) -> Dict[str, Any]:
        try:
            params = {}
            if risk_level:
                params["baseurl"] = risk_level
            url = self._build_url("JSON/core/view/alerts/", params)
            self._log_request("GET", url)
            response = requests.get(url)
            self._log_response(response)
            return {"status": "success", "alerts": response.json().get("alerts", []), "message": "Alerts retrieved successfully"}
        except Exception as e:
            self.logger.error(f"Error getting alerts: {e}")
            return {"status": "error", "message": str(e)}

    def generate_report(self, report_format: str = "html") -> Dict[str, Any]:
        """Generate scan report with retry mechanism"""
        max_retries = 3
        retry_delay = 2  # seconds
        
        for attempt in range(max_retries):
            try:
                # First verify ZAP is still responsive
                if not self._verify_zap_running():
                    return {
                        "status": "error",
                        "message": "ZAP is not responding. Please check if ZAP is still running."
                    }

                # Get alerts first to ensure we have data
                alerts = self.get_alerts()
                if alerts["status"] != "success":
                    return alerts

                # Prepare report data
                data = {
                    "title": "ZAP Scan Report",
                    "template": report_format,
                    "theme": "original",
                    "description": "Report generated by AutoVAPT",
                    "contexts": "",
                    "sites": "",
                    "sections": "",
                    "includedConfidence": "",
                    "includedRisk": "",
                    "reportFileName": "zap-report",
                    "reportFileNamePattern": "",
                    "reportDir": "",
                    "display": False
                }

                # Set longer timeout for report generation
                timeout = 30  # seconds
                url = self._build_url("JSON/reports/action/generate/")
                self._log_request("POST", url, data=data)
                
                response = requests.post(url, data=data, timeout=timeout)
                self._log_response(response)
                
                if response.status_code == 200:
                    report_data = response.json()
                    
                    # Add alerts to the response for backup
                    report_data["alerts"] = alerts["alerts"]
                    
                    return {
                        "status": "success",
                        "report": report_data,
                        "message": "Report generated successfully"
                    }
                else:
                    self.logger.warning(f"Report generation failed with status {response.status_code}")
                    
            except requests.exceptions.Timeout:
                self.logger.warning(f"Report generation timed out (attempt {attempt + 1}/{max_retries})")
                if attempt == max_retries - 1:
                    # On final attempt, return alerts as fallback
                    return {
                        "status": "partial",
                        "report": {"alerts": alerts["alerts"]},
                        "message": "Report generation timed out, returning alerts only"
                    }
                    
            except requests.exceptions.ConnectionError as e:
                self.logger.warning(f"Connection error during report generation (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt == max_retries - 1:
                    # On final attempt, return alerts as fallback
                    return {
                        "status": "partial",
                        "report": {"alerts": alerts["alerts"]},
                        "message": "Connection error during report generation, returning alerts only"
                    }
                    
            except Exception as e:
                self.logger.error(f"Error generating report: {e}")
                return {"status": "error", "message": str(e)}
                
            # Wait before retrying
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
        
        # If we get here, all retries failed
        return {
            "status": "error",
            "message": "Failed to generate report after multiple attempts"
        }

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        pass

    OWASP_TOP_10_MAPPING = {
        # Example mappings (expand as needed)
        'SQL Injection': 'A03:2021 - Injection',
        'Cross Site Scripting': 'A07:2021 - Cross-Site Scripting (XSS)',
        'Broken Authentication': 'A02:2021 - Cryptographic Failures',
        'Sensitive Data Exposure': 'A03:2021 - Injection',
        'Security Misconfiguration': 'A05:2021 - Security Misconfiguration',
        'Insecure Deserialization': 'A08:2021 - Software and Data Integrity Failures',
        'Using Components with Known Vulnerabilities': 'A06:2021 - Vulnerable and Outdated Components',
        'Insufficient Logging & Monitoring': 'A09:2021 - Security Logging and Monitoring Failures',
        # ... add more as needed ...
    }

    def process_alerts_with_owasp(self, alerts):
        """
        Process ZAP alerts, mapping to OWASP Top 10 and CVE if available.
        Returns a list of dicts with vulnerability details.
        """
        processed = []
        for alert in alerts:
            name = alert.get('alert')
            severity = alert.get('risk')
            description = alert.get('description')
            url = alert.get('url')
            references = alert.get('reference', '')
            cve = None
            # Try to extract CVE from references
            if 'CVE-' in references:
                for part in references.split():
                    if part.startswith('CVE-'):
                        cve = part
                        break
            # Map to OWASP Top 10
            owasp = None
            for key in self.OWASP_TOP_10_MAPPING:
                if key.lower() in name.lower():
                    owasp = self.OWASP_TOP_10_MAPPING[key]
                    break
            processed.append({
                'name': name,
                'severity': severity,
                'cve': cve,
                'owasp': owasp,
                'description': description,
                'url': url
            })
        return processed 