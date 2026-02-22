import subprocess
import os
import json
from typing import List, Dict, Any
import nmap

class PortScanner:
    def __init__(self, target: str, output_dir: str):
        self.target = target
        self.output_dir = output_dir
        self.results = []
        # Set nmap path for python-nmap
        self.nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
        
    def run_nmap(self) -> Dict[str, Any]:
        """Run nmap scan to discover open ports and services"""
        try:
            output_file = os.path.join(self.output_dir, "nmap_results.txt")
            
            # Use direct subprocess call with full path
            cmd = [self.nmap_path, "-p-", "--open", "-sV", "-sC", "-T4", "-oN", output_file, self.target]
            subprocess.run(cmd, check=True)
            
            # Parse nmap results using python-nmap with configured path
            nm = nmap.PortScanner()
            nm.nmap_path = self.nmap_path
            nm.scan(self.target, arguments='-p- -sV -sC')
            
            ports_info = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]
                        ports_info.append({
                            'port': port,
                            'state': service['state'],
                            'name': service['name'],
                            'product': service.get('product', ''),
                            'version': service.get('version', ''),
                            'extrainfo': service.get('extrainfo', '')
                        })
            
            return {
                'status': 'success',
                'ports': ports_info,
                'output_file': output_file
            }
        except Exception as e:
            print(f"Error running nmap: {str(e)}")
            return {'status': 'error', 'message': str(e)}
            
    def run_masscan(self) -> Dict[str, Any]:
        """Run masscan for quick port discovery"""
        try:
            output_file = os.path.join(self.output_dir, "masscan_results.txt")
            cmd = f"masscan -p1-65535 --rate 10000 -oL {output_file} {self.target}"
            subprocess.run(cmd, shell=True, check=True)
            
            # Parse masscan results
            ports = []
            with open(output_file, 'r') as f:
                for line in f:
                    if line.startswith('open'):
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            ports.append({
                                'port': parts[3],
                                'state': 'open',
                                'protocol': parts[2]
                            })
            
            return {
                'status': 'success',
                'ports': ports,
                'output_file': output_file
            }
        except Exception as e:
            print(f"Error running masscan: {str(e)}")
            return {'status': 'error', 'message': str(e)}
            
    def run(self) -> Dict[str, Any]:
        """Run all port scanning tools and combine results"""
        # Run nmap scan
        nmap_results = self.run_nmap()
        
        # Run masscan (only if available)
        masscan_results = {'status': 'error', 'message': 'masscan not available'}
        try:
            masscan_results = self.run_masscan()
        except:
            pass
        
        # Combine results
        all_ports = set()
        ports_info = {}
        
        if nmap_results['status'] == 'success':
            for port_info in nmap_results['ports']:
                port = port_info['port']
                all_ports.add(port)
                ports_info[port] = port_info
                
        if masscan_results['status'] == 'success':
            for port_info in masscan_results['ports']:
                port = port_info['port']
                all_ports.add(port)
                if port not in ports_info:
                    ports_info[port] = port_info
                    
        # Save combined results
        output_file = os.path.join(self.output_dir, "all_ports.json")
        with open(output_file, 'w') as f:
            json.dump({
                'total_ports': len(all_ports),
                'ports': list(ports_info.values())
            }, f, indent=4)
            
        return {
            'status': 'success',
            'total_ports': len(all_ports),
            'ports': list(ports_info.values()),
            'output_file': output_file
        }
        
def scan_ports(target: str, output_dir: str) -> Dict[str, Any]:
    """Main function to run port scanning"""
    scanner = PortScanner(target, output_dir)
    return scanner.run() 