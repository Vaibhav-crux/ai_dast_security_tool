import subprocess
import os
import tempfile
from typing import List, Dict, Any
import json

class SubdomainEnumerator:
    def __init__(self, target: str, output_dir: str):
        self.target = target
        self.output_dir = output_dir
        self.results = []
        
    def run_subfinder(self) -> List[str]:
        """Run subfinder to discover subdomains"""
        try:
            output_file = os.path.join(self.output_dir, "subfinder_results.txt")
            cmd = f"subfinder -d {self.target} -o {output_file}"
            subprocess.run(cmd, shell=True, check=True)
            
            with open(output_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            return subdomains
        except Exception as e:
            print(f"Error running subfinder: {str(e)}")
            return []
            
    def run_amass(self) -> List[str]:
        """Run amass to discover subdomains"""
        try:
            output_file = os.path.join(self.output_dir, "amass_results.txt")
            cmd = f"amass enum -passive -d {self.target} -o {output_file}"
            subprocess.run(cmd, shell=True, check=True)
            
            with open(output_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            return subdomains
        except Exception as e:
            print(f"Error running amass: {str(e)}")
            return []
            
    def run_assetfinder(self) -> List[str]:
        """Run assetfinder to discover subdomains"""
        try:
            output_file = os.path.join(self.output_dir, "assetfinder_results.txt")
            cmd = f"assetfinder --subs-only {self.target} > {output_file}"
            subprocess.run(cmd, shell=True, check=True)
            
            with open(output_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            return subdomains
        except Exception as e:
            print(f"Error running assetfinder: {str(e)}")
            return []
            
    def run(self) -> Dict[str, Any]:
        """Run all subdomain enumeration tools and combine results"""
        all_subdomains = set()
        
        # Run each tool
        subfinder_results = self.run_subfinder()
        amass_results = self.run_amass()
        assetfinder_results = self.run_assetfinder()
        
        # Combine results
        all_subdomains.update(subfinder_results)
        all_subdomains.update(amass_results)
        all_subdomains.update(assetfinder_results)
        
        # Save combined results
        output_file = os.path.join(self.output_dir, "all_subdomains.txt")
        with open(output_file, 'w') as f:
            for subdomain in sorted(all_subdomains):
                f.write(f"{subdomain}\n")
                
        return {
            "status": "success",
            "total_subdomains": len(all_subdomains),
            "subdomains": list(all_subdomains),
            "output_file": output_file
        }
        
def enumerate_subdomains(target: str, output_dir: str) -> Dict[str, Any]:
    """Main function to run subdomain enumeration"""
    enumerator = SubdomainEnumerator(target, output_dir)
    return enumerator.run() 