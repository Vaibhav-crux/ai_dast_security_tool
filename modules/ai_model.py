"""AI model integration for AutoDAST."""

from llama_cpp import Llama
import os
import json
from typing import Dict, List, Optional, Any
from pathlib import Path
from dotenv import load_dotenv
from functools import lru_cache
from datetime import datetime

load_dotenv()

class AIModel:
    """AI model for vulnerability analysis and chat assistance."""
    
    def __init__(self, model_path: str):
        """Initialize the AI model.
        
        Args:
            model_path: Path to the GGUF model file
        """
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")
            
        # Load model
        self.model = Llama(
            model_path=model_path,
            n_ctx=2048,  # Context window
            n_threads=4,  # Number of CPU threads to use
            n_gpu_layers=0,  # CPU only for now
            verbose=False
        )
        
        # Load prompt templates
        template_dir = os.path.join(os.path.dirname(__file__), "prompts")
        self.templates = self._load_templates(template_dir)
        
    def _load_templates(self, template_dir: str) -> Dict[str, str]:
        """Load prompt templates from files.
        
        Args:
            template_dir: Directory containing prompt template files
            
        Returns:
            Dictionary of loaded templates
        """
        templates = {}
        
        if not os.path.exists(template_dir):
            print(f"Warning: Template directory not found: {template_dir}")
            return templates
            
        for filename in os.listdir(template_dir):
            if filename.endswith(".txt"):
                template_name = filename[:-4]  # Remove .txt extension
                template_path = os.path.join(template_dir, filename)
                try:
                    with open(template_path, 'r') as f:
                        templates[template_name] = f.read()
                except Exception as e:
                    print(f"Error loading template {filename}: {e}")
                    
        return templates
        
    def chat(self, message: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        """Process a chat message and return a response.
        
        Args:
            message: The user's message
            context: Optional context dictionary containing scan results, etc.
            
        Returns:
            Dictionary containing response and status
        """
        try:
            # Prepare prompt
            if context and context.get('findings'):
                findings_summary = []
                for vuln in context['findings'][:5]:  # Limit to 5 findings for context
                    findings_summary.append(
                        f"- {vuln.get('name', 'Unknown')}: {vuln.get('severity', 'Unknown')} severity"
                    )
                
                prompt = f"""Context:
Target URL: {context.get('target_url', 'Not specified')}
Recent Findings:
{chr(10).join(findings_summary)}

User: {message}
Assistant: """
            else:
                prompt = f"""You are a cybersecurity assistant helping to understand security concepts and findings.

User: {message}
Assistant: """
            
            # Generate response
            response = self.model.create_completion(
                prompt,
                max_tokens=1024,
                temperature=0.7,
                top_p=0.95,
                stop=["User:", "Human:", "</response>"]
            )
            
            return {
                "status": "success",
                "response": response["choices"][0]["text"].strip()
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Chat failed: {str(e)}"
            }

    def analyze_vulnerability(self, 
                            vulnerability_data: Dict[str, Any],
                            context: Optional[str] = None) -> Dict[str, Any]:
        """Analyze vulnerability data using AI model"""
        try:
            # Prepare prompt
            prompt = self._prepare_vulnerability_prompt(vulnerability_data, context)
            
            # Generate response with optimized settings
            response = self.model.create_completion(
                prompt,
                max_tokens=500,
                temperature=0.7,
                top_p=0.9,
                repeat_penalty=1.1,
                top_k=40,
                echo=False
            )
            
            # Process response
            analysis = self._process_ai_response(response)
            
            return {
                "status": "success",
                "analysis": analysis,
                "raw_response": response
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }

    def analyze_scan_results(self, vulnerabilities: List[Dict[str, Any]], context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze vulnerability scan results (optimized for small/fast models).
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            context: Additional context about the scan
            
        Returns:
            Dictionary containing analysis results
        """
        try:
            # Standard mitigations for common vulnerability types
            STANDARD_MITIGATIONS = {
                'sql injection': 'Use parameterized queries and ORM, validate and sanitize all user inputs, and apply least privilege to database accounts.',
                'xss': 'Implement output encoding, use Content Security Policy (CSP), and sanitize user input.',
                'cross site scripting': 'Implement output encoding, use Content Security Policy (CSP), and sanitize user input.',
                'open redirect': 'Avoid using user input in redirects, validate and whitelist redirect URLs.',
                'lfi': 'Validate and sanitize file paths, use allow-lists, and disable unnecessary file inclusion features.',
                'rfi': 'Validate and sanitize file paths, use allow-lists, and disable remote file inclusion.',
                'ssrf': 'Validate and sanitize URLs, block requests to internal resources, and use network segmentation.',
                'sensitive data exposure': 'Use strong encryption for data at rest and in transit, and avoid exposing sensitive data in responses.',
                'directory brute force': 'Restrict directory listing, use proper access controls, and monitor for brute force attempts.',
                'subdomain enumeration': 'Use DNS security features, monitor for unauthorized subdomains, and implement proper access controls.',
                'port scan': 'Restrict unnecessary open ports, use firewalls, and monitor network traffic.',
                'security headers': 'Implement security headers like CSP, X-Frame-Options, X-XSS-Protection, and Strict-Transport-Security.',
                'cve': 'Apply the latest security patches and updates for all software components.',
                'information disclosure': 'Remove sensitive information from error messages and public files, and restrict access to internal resources.',
                'default credentials': 'Change all default credentials and enforce strong password policies.',
                'weak authentication': 'Implement multi-factor authentication and enforce strong password requirements.',
                'csrf': 'Use anti-CSRF tokens and verify the origin of requests.',
                'file upload': 'Validate file types, use anti-virus scanning, and store uploads outside the web root.',
                'insecure deserialization': 'Avoid deserializing untrusted data and use integrity checks.',
                'command injection': 'Validate and sanitize all user inputs, and avoid using shell commands with user data.',
                'path traversal': 'Sanitize file paths and use allow-lists for file access.',
                'hardcoded credentials': 'Remove hardcoded credentials from code and use secure vaults for secrets.',
            }

            # Limit to top 5 vulnerabilities by severity
            max_vulns = 5
            severity_order = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4, 'info': 5}
            sorted_vulns = sorted(vulnerabilities, key=lambda v: severity_order.get(v.get('severity', '').lower(), 99))
            trimmed_vulns = sorted_vulns[:max_vulns]
            extra_vulns = len(vulnerabilities) - len(trimmed_vulns)

            # Prepare vulnerability summary (only key fields, very short description)
            vuln_summary = []
            for vuln in trimmed_vulns:
                desc = vuln.get('description', 'No description')
                if len(desc) > 100:
                    desc = desc[:100] + '...'
                
                vuln_summary.append(f"- {vuln.get('name', 'Unknown')} ({vuln.get('severity', 'Unknown')}): {desc}")

            # Create hybrid analysis combining AI and knowledge base
            analysis = {
                'summary': f"Found {len(vulnerabilities)} vulnerabilities. Top {len(trimmed_vulns)} analyzed.",
                'critical_findings': [],
                'recommendations': [],
                'risk_score': 0,
                'ai_insights': []
            }

            # Calculate risk score
            severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}
            total_risk = 0
            for vuln in vulnerabilities:
                severity = vuln.get('severity', '').lower()
                total_risk += severity_weights.get(severity, 1)
            analysis['risk_score'] = min(total_risk, 100)  # Cap at 100

            # Map risk_score to risk_level
            if analysis['risk_score'] >= 80:
                analysis['risk_level'] = 'Critical'
            elif analysis['risk_score'] >= 60:
                analysis['risk_level'] = 'High'
            elif analysis['risk_score'] >= 40:
                analysis['risk_level'] = 'Medium'
            elif analysis['risk_score'] >= 20:
                analysis['risk_level'] = 'Low'
            else:
                analysis['risk_level'] = 'Info'

            # Generate recommendations using knowledge base
            for vuln in trimmed_vulns:
                vuln_type = vuln.get('name', '').lower()
                for key, mitigation in STANDARD_MITIGATIONS.items():
                    if key in vuln_type:
                        # Add both mitigation and remediation fields
                        vuln['mitigation'] = mitigation
                        vuln['remediation'] = mitigation  # For now, use the same text for both; can be split if needed
                        analysis['recommendations'].append({
                            'vulnerability': vuln.get('name', 'Unknown'),
                            'mitigation': mitigation,
                            'priority': vuln.get('severity', 'Unknown')
                        })
                        break

            # Add AI insights for top vulnerabilities
            if trimmed_vulns:
                try:
                    # Create a simple prompt for AI analysis
                    prompt = f"""Analyze these top {len(trimmed_vulns)} security vulnerabilities:\n\n{chr(10).join(vuln_summary)}\n\nProvide 2-3 key insights about the overall security posture. Keep it brief and actionable."""
                    ai_response = self.model.create_completion(
                        prompt,
                        max_tokens=200,
                        temperature=0.7,
                        top_p=0.9
                    )
                    ai_text = ai_response["choices"][0]["text"].strip()
                    analysis['ai_insights'] = [ai_text]
                except Exception as e:
                    analysis['ai_insights'] = ["AI analysis unavailable - using knowledge base recommendations"]

            # Add additional_notes
            analysis['additional_notes'] = analysis['ai_insights'][0] if analysis.get('ai_insights') else 'No additional notes'

            return {
                "status": "success",
                "analysis": analysis,
                "total_vulnerabilities": len(vulnerabilities),
                "analyzed_vulnerabilities": len(trimmed_vulns)
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Analysis failed: {str(e)}"
            }

    def generate_report(self, 
                       analysis_results: Dict[str, Any],
                       format: str = "markdown") -> str:
        """Generate a formatted report from analysis results"""
        try:
            if format.lower() == "markdown":
                return self._generate_markdown_report(analysis_results)
            else:
                return str(analysis_results)
        except Exception as e:
            return f"Error generating report: {str(e)}"

    def _prepare_vulnerability_prompt(self, 
                                    vulnerability_data: Dict[str, Any],
                                    context: Optional[str]) -> str:
        """Prepare prompt for vulnerability analysis"""
        prompt = f"""Analyze this security vulnerability:

Name: {vulnerability_data.get('name', 'Unknown')}
Severity: {vulnerability_data.get('severity', 'Unknown')}
Description: {vulnerability_data.get('description', 'No description')}
Location: {vulnerability_data.get('location', 'Unknown')}

Context: {context or 'No additional context'}

Provide:
1. Risk assessment
2. Immediate mitigation steps
3. Long-term prevention measures

Analysis:"""
        return prompt

    def _prepare_report_prompt(self, 
                             analysis_results: Dict[str, Any],
                             format: str) -> str:
        """Prepare prompt for report generation"""
        prompt = f"""Generate a {format} security report based on this analysis:

{json.dumps(analysis_results, indent=2)}

Report:"""
        return prompt

    def _process_ai_response(self, response: str) -> Dict[str, Any]:
        """Process AI model response"""
        try:
            # Extract text from response
            if isinstance(response, dict) and 'choices' in response:
                text = response['choices'][0]['text'].strip()
            else:
                text = str(response)
            
            # Simple parsing - can be enhanced
            return {
                'text': text,
                'confidence': 0.8,  # Default confidence
                'key_points': text.split('\n')[:3]  # First 3 lines as key points
            }
        except Exception as e:
            return {
                'text': str(response),
                'confidence': 0.5,
                'error': str(e)
            }

    def _generate_markdown_report(self, analysis: Dict[str, Any]) -> str:
        """Generate markdown format report"""
        report = f"""# Security Analysis Report

## Summary
{analysis.get('summary', 'No summary available')}

## Risk Score
**Overall Risk Score: {analysis.get('risk_score', 0)}/100**

## Key Findings
"""
        
        for finding in analysis.get('critical_findings', []):
            report += f"- {finding}\n"
        
        report += "\n## Recommendations\n"
        for rec in analysis.get('recommendations', []):
            report += f"### {rec.get('vulnerability', 'Unknown')} ({rec.get('priority', 'Unknown')})\n"
            report += f"{rec.get('mitigation', 'No mitigation available')} - {rec.get('remediation', 'No remediation available')}\n\n"
        
        if analysis.get('ai_insights'):
            report += "## AI Insights\n"
            for insight in analysis['ai_insights']:
                report += f"{insight}\n\n"
        
        return report

    def __del__(self):
        """Cleanup when object is destroyed"""
        try:
            if hasattr(self, 'model'):
                del self.model
        except:
            pass 