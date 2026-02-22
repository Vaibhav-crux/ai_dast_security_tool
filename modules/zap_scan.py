import time
import json
import os
from typing import Dict, Any
from zapv2 import ZAPv2

class ZAPScanner:
    def __init__(self, target: str, output_dir: str, api_key: str = None):
        self.target = target
        self.output_dir = output_dir
        self.api_key = api_key
        # Initialize ZAP API client
        self.zap = ZAPv2(apikey=self.api_key)

    def start_zap(self) -> None:
        """Start ZAP and wait for it to be ready."""
        print("Starting ZAP...")
        # Wait for ZAP to start
        time.sleep(5)
        print("ZAP started successfully.")

    def run_scan(self) -> Dict[str, Any]:
        """Run a ZAP scan on the target and retrieve results."""
        try:
            self.start_zap()
            print(f"Starting ZAP scan on {self.target}")
            # Start the scan
            scan_id = self.zap.spider.scan(self.target)
            # Wait for the spider to complete
            while int(self.zap.spider.status(scan_id)) < 100:
                print(f"Spider progress: {self.zap.spider.status(scan_id)}%")
                time.sleep(5)
            print("Spider completed.")
            # Start the active scan
            ascan_id = self.zap.ascan.scan(self.target)
            # Wait for the active scan to complete
            while int(self.zap.ascan.status(ascan_id)) < 100:
                print(f"Active scan progress: {self.zap.ascan.status(ascan_id)}%")
                time.sleep(5)
            print("Active scan completed.")
            # Retrieve the alerts
            alerts = self.zap.core.alerts()
            # Save the results
            output_file = os.path.join(self.output_dir, "zap_results.json")
            with open(output_file, 'w') as f:
                json.dump(alerts, f, indent=4)
            return {
                "status": "success",
                "alerts": alerts,
                "output_file": output_file
            }
        except Exception as e:
            print(f"Error running ZAP scan: {str(e)}")
            return {
                "status": "error",
                "message": str(e)
            }

def scan_with_zap(target: str, output_dir: str, api_key: str = None) -> Dict[str, Any]:
    """Main function to run a ZAP scan."""
    scanner = ZAPScanner(target, output_dir, api_key)
    return scanner.run_scan() 