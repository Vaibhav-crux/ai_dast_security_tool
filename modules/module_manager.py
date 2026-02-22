import os
import json
from typing import Dict, Any, List
from datetime import datetime
from .subdomain_enum import enumerate_subdomains
from .port_scan import scan_ports
from .advanced_pentest import run_pentest

class ModuleManager:
    def __init__(self, target: str, output_dir: str = None):
        self.target = target
        self.output_dir = output_dir or self._create_output_dir()
        self.modules = {
            "Subdomain Enumeration": enumerate_subdomains,
            "Port Scanning": scan_ports,
            "Advanced Pentest": run_pentest,
            # Add more modules here as they are implemented
        }
        
    def _create_output_dir(self) -> str:
        """Create output directory for scan results"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join("scan_results", f"{self.target}_{timestamp}")
        os.makedirs(output_dir, exist_ok=True)
        return output_dir
        
    def run_module(self, module_name: str) -> Dict[str, Any]:
        """Run a specific module"""
        if module_name not in self.modules:
            return {
                "status": "error",
                "message": f"Module {module_name} not found"
            }
            
        try:
            module_func = self.modules[module_name]
            return module_func(self.target, self.output_dir)
        except Exception as e:
            return {
                "status": "error",
                "message": f"Error running {module_name}: {str(e)}"
            }
            
    def run_modules(self, module_names: List[str]) -> Dict[str, Any]:
        """Run multiple modules and combine their results"""
        results = {}
        errors = []
        
        for module_name in module_names:
            result = self.run_module(module_name)
            results[module_name] = result
            
            if result["status"] == "error":
                errors.append(f"{module_name}: {result['message']}")
                
        # Save combined results
        output_file = os.path.join(self.output_dir, "scan_summary.json")
        with open(output_file, 'w') as f:
            json.dump({
                "target": self.target,
                "timestamp": datetime.now().isoformat(),
                "results": results,
                "errors": errors
            }, f, indent=4)
            
        return {
            "status": "success" if not errors else "error",
            "results": results,
            "errors": errors,
            "output_file": output_file
        }
        
    def get_available_modules(self) -> List[str]:
        """Get list of available modules"""
        return list(self.modules.keys())
        
def run_scan(target: str, modules: List[str], output_dir: str = None) -> Dict[str, Any]:
    """Main function to run a scan with specified modules"""
    manager = ModuleManager(target, output_dir)
    return manager.run_modules(modules) 