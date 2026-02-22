import os
import requests
import json
from dotenv import load_dotenv
from typing import List, Dict, Any

# Load environment variables
load_dotenv()

ZAP_API_URL = os.getenv("ZAP_API_URL", "http://localhost:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_zap_alerts() -> List[Dict[str, Any]]:
    """Fetch alerts (vulnerabilities) from OWASP ZAP."""
    try:
        response = requests.get(
            f"{ZAP_API_URL}/JSON/alert/view/alerts/",
            params={"apikey": ZAP_API_KEY}
        )
        response.raise_for_status()
        return response.json().get("alerts", [])
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching ZAP alerts: {e}")
        return []

def fetch_cve_details(cve_id: str) -> List[Dict[str, Any]]:
    """Fetch CVE details from NVD API."""
    try:
        response = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id},
            headers={"User-Agent": "ZAP-CVE-Enricher/1.0"}
        )
        response.raise_for_status()
        data = response.json()
        return data.get("vulnerabilities", [])
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching CVE data for {cve_id}: {e}")
        return []

def extract_cves_from_zap(alerts: List[Dict[str, Any]]) -> List[str]:
    """Extract CVE IDs from ZAP alerts."""
    cves = set()
    for alert in alerts:
        # Check references for CVE IDs
        refs = alert.get("reference", "")
        if "CVE-" in refs:
            for part in refs.split():
                if part.startswith("CVE-"):
                    cves.add(part.strip(",.;:))]"))
        # Check evidence for CVE IDs
        evidence = alert.get("evidence", "")
        if "CVE-" in evidence:
            for part in evidence.split():
                if part.startswith("CVE-"):
                    cves.add(part.strip(",.;:))]"))
    return list(cves)

def enrich_zap_alerts_with_cve(vulnerabilities):
    """Enrich ZAP alerts with CVE and CVSS info."""
    for vuln in vulnerabilities:
        cve = vuln.get('cve')
        if cve:
            nvd_data = fetch_cve_details(cve)
            if nvd_data:
                vuln['cve_id'] = cve
                vuln['cvss'] = nvd_data.get('cvss', 'N/A')
    return vulnerabilities

def display_cve_details(vulnerabilities: List[Dict[str, Any]]):
    """Display CVE details in a structured format."""
    if not vulnerabilities:
        print("No CVE details found.")
        return
    for vuln in vulnerabilities:
        cve = vuln.get("nvd", {}).get("cve", {})
        print(f"\n[+] CVE ID: {cve.get('id', '')}")
        print(f"Published: {cve.get('published', '')}")
        # Extract CVSS metrics
        metrics = cve.get("metrics", {})
        if metrics:
            cvss_metrics = metrics.get("cvssMetricV31", [{}])[0]
            if cvss_metrics:
                cvss_data = cvss_metrics.get("cvssData", {})
                print(f"CVSS Score: {cvss_data.get('baseScore', 'N/A')} ({cvss_data.get('baseSeverity', 'N/A')})")
                print(f"Vector: {cvss_data.get('vectorString', 'N/A')}")
        # Print description
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                print(f"Description: {desc.get('value', '')}")
                break
        print("-" * 50)

if __name__ == "__main__":
    enriched = enrich_zap_alerts_with_cve(fetch_zap_alerts())
    display_cve_details(enriched) 