"""Worker threads for AutoDAST scanning and testing operations."""

from PyQt6.QtCore import QThread, pyqtSignal
import time
import os
from datetime import datetime
import json
from .zap_automation import ZAPAutomation
from .zap_cve_enricher import enrich_zap_alerts_with_cve
from modules.advanced_pentest import PentestingAutomation

class VAScanWorker(QThread):
    """Worker thread for vulnerability assessment scanning."""
    progress = pyqtSignal(str, int)
    finished = pyqtSignal(dict)

    def __init__(self, target_url: str, output_dir: str):
        super().__init__()
        self.target_url = target_url
        self.output_dir = output_dir
        self._is_running = True
        self.zap = ZAPAutomation()
        
    def stop(self):
        """Stop the current scan"""
        self._is_running = False
        
    def run(self):
        """Run vulnerability assessment scan"""
        try:
            if not self._is_running:
                return
                
            self.progress.emit("Connecting to ZAP...", 10)
            
            # Start the scan
            self.progress.emit("Starting scan...", 20)
            scan_result = self.zap.start_scan(self.target_url)
            if scan_result["status"] != "success":
                raise Exception(f"Failed to start scan: {scan_result['message']}")

            scan_id = scan_result["ascan_id"]
            while self._is_running:
                progress_result = self.zap.get_scan_progress(scan_id)
                if progress_result["status"] != "success":
                    raise Exception(f"Failed to get scan progress: {progress_result['message']}")
                
                progress = int(progress_result["progress"])
                self.progress.emit(f"Scanning: {progress}%", 20 + (progress * 0.6))
                
                if progress >= 100:
                    break
                    
                time.sleep(5)

            if not self._is_running:
                    return
                
            self.progress.emit("Getting alerts...", 90)
            alerts_result = self.zap.get_alerts()
            if alerts_result["status"] != "success":
                raise Exception(f"Failed to get alerts: {alerts_result['message']}")

            # Process alerts with OWASP mapping and CVE enrichment
            processed_alerts = self.zap.process_alerts_with_owasp(alerts_result["alerts"])
            enriched_alerts = enrich_zap_alerts_with_cve(processed_alerts)

            self.progress.emit("Scan completed successfully", 100)
            self.finished.emit({
                "status": "success",
                "vulnerabilities": enriched_alerts
            })
                
        except Exception as e:
            self.finished.emit({
                "status": "error",
                "message": str(e)
            })

class PentestWorker(QThread):
    """Worker thread for penetration testing."""
    progress = pyqtSignal(str, int)
    finished = pyqtSignal(dict)

    def __init__(self, target_url: str, output_dir: str):
        super().__init__()
        self.target_url = target_url
        self.output_dir = output_dir
        self._is_running = True

    def stop(self):
        """Stop the current pentest"""
        self._is_running = False

    def run(self):
        """Run penetration test using real PentestingAutomation"""
        try:
            self.progress.emit("Initializing pentest...", 0)
            pentester = PentestingAutomation(self.target_url, self.output_dir)
            total_steps = 4  # Total number of steps
            step = 0

            # 1. Reconnaissance (Subdomain Enumeration)
            step += 1
            self.progress.emit(f"Step {step}/{total_steps}: Enumerating subdomains...", int(100 * (step -1) / total_steps))
            recon_results = pentester.enumerate_subdomains()
            if not self._is_running: return

            # 2. Port Scanning
            step += 1
            self.progress.emit(f"Step {step}/{total_steps}: Scanning ports...", int(100 * (step - 1) / total_steps))
            port_results = pentester.scan_ports()
            if not self._is_running: return

            # 3. Directory Bruteforcing
            step += 1
            self.progress.emit(f"Step {step}/{total_steps}: Bruteforcing directories...", int(100 * (step - 1) / total_steps))
            dir_results = pentester.directory_bruteforce()
            if not self._is_running: return

            # 4. XSS Scanning
            step += 1
            self.progress.emit(f"Step {step}/{total_steps}: Scanning for XSS...", int(100 * (step - 1) / total_steps))
            xss_results = pentester.xss_scan()
            if not self._is_running: return

            # Reporting
            self.progress.emit("Generating pentest report...", 95)
            results = {
                "subdomains": recon_results,
                "ports": port_results,
                "directories": dir_results,
                "xss": xss_results,
            }
            # Save results to file
            report_path = os.path.join(self.output_dir, "pentest_results.json")
            with open(report_path, 'w') as f:
                json.dump(results, f, indent=4, default=str) # Use default=str to handle non-serializable data
            self.progress.emit("Pentest complete!", 100)
            self.finished.emit({
                "status": "success",
                "results": results,
                "report_file": report_path
            })
        except Exception as e:
            self.finished.emit({
                "status": "error",
                "message": str(e)
            }) 