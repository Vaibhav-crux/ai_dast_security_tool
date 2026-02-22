"""
AutoVAPT - Automated Vulnerability Assessment & Penetration Testing Tool
Main application module
"""

import sys
import os
import json
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                            QHBoxLayout, QLabel, QLineEdit, QPushButton,
                            QTextEdit, QGroupBox, QScrollArea, QProgressBar, 
                            QMessageBox, QFileDialog, QTableWidget, QTableWidgetItem,
                            QHeaderView, QFormLayout, QSplitter, QInputDialog, QDialog)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QFont, QIcon, QMovie, QBrush, QColor
from modules.module_manager import ModuleManager
from modules.zap_automation import ZAPAutomation
from modules.advanced_pentest import run_pentesting_for_vulns, get_owasp_color
from modules.zap_cve_enricher import enrich_zap_alerts_with_cve
from modules.ai_model import AIModel
from modules.workers import VAScanWorker, PentestWorker
from modules.ui.loading_indicator import LoadingIndicator
from modules.report_generator import VAPTReportGenerator
from datetime import datetime
from dotenv import load_dotenv
import time
from modules.malware_analysis import scan_targets_sync

class AutoVAPT(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AutoVAPT - Automated Vulnerability Assessment & Penetration Testing")
        self.setGeometry(100, 100, 1200, 800)
        
        # Initialize variables
        self.vulnerabilities = []
        self.pt_results = {}
        self.target_url = ""
        self.output_dir = ""
        self.va_complete = False
        self.pt_complete = False
        
        # Initialize loading indicator
        self.loading = LoadingIndicator(self)
        
        # Initialize AI model for chat
        try:
            model_path = os.path.join(os.path.dirname(__file__), "models", "q4_0-orca-mini-3b.gguf")
            self.chat_model = AIModel(model_path)
        except Exception as e:
            self.chat_model = None
            print(f"Error initializing AI model: {e}")
        
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface"""
        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)

        # Top splitter (VA and PT)
        top_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left side - Vulnerability Assessment
        va_widget = QWidget()
        va_layout = QVBoxLayout(va_widget)
        va_group = QGroupBox("Vulnerability Assessment")
        va_inner = QVBoxLayout()

        # VA Input fields
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target URL:"))
        self.target_url_input = QLineEdit()
        target_layout.addWidget(self.target_url_input)
        va_inner.addLayout(target_layout)

        output_layout = QHBoxLayout()
        output_layout.addWidget(QLabel("Output Directory:"))
        self.output_dir_input = QLineEdit()
        output_layout.addWidget(self.output_dir_input)
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_output)
        output_layout.addWidget(browse_button)
        va_inner.addLayout(output_layout)

        # VA Controls
        va_controls = QHBoxLayout()
        self.start_va_button = QPushButton("Start VA Scan")
        self.start_va_button.clicked.connect(self.start_va_scan)
        self.stop_va_button = QPushButton("Stop Scan")
        self.stop_va_button.clicked.connect(self.stop_scan)
        va_controls.addWidget(self.start_va_button)
        va_controls.addWidget(self.stop_va_button)
        va_inner.addLayout(va_controls)
        
        # VA Results Table
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(5)
        self.vuln_table.setHorizontalHeaderLabels(["Vulnerability", "Severity", "OWASP", "Description", "URL"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        va_inner.addWidget(self.vuln_table)

        # VA Progress Bar (moved below the table)
        self.va_progress = QProgressBar()
        self.va_progress.hide()
        va_inner.addWidget(self.va_progress)

        va_group.setLayout(va_inner)
        va_layout.addWidget(va_group)
        top_splitter.addWidget(va_widget)

        # Right side - Penetration Testing
        pt_widget = QWidget()
        pt_layout = QVBoxLayout(pt_widget)
        pt_group = QGroupBox("Penetration Testing")
        pt_inner = QVBoxLayout()

        # PT Controls
        pt_controls = QHBoxLayout()
        self.start_pt_button = QPushButton("Start Pentest")
        self.start_pt_button.clicked.connect(self.start_pentest)
        self.stop_pt_button = QPushButton("Stop Pentest")
        self.stop_pt_button.clicked.connect(self.stop_pentest)
        pt_controls.addWidget(self.start_pt_button)
        pt_controls.addWidget(self.stop_pt_button)
        pt_inner.addLayout(pt_controls)

        # PT Results Display
        self.pt_results_display = QTextEdit()
        self.pt_results_display.setReadOnly(True)
        pt_inner.addWidget(self.pt_results_display)

        # PT Progress Bar (moved below the results)
        self.pt_progress = QProgressBar()
        self.pt_progress.hide()
        pt_inner.addWidget(self.pt_progress)

        pt_group.setLayout(pt_inner)
        pt_layout.addWidget(pt_group)
        top_splitter.addWidget(pt_widget)

        # Add top splitter to main layout
        main_layout.addWidget(top_splitter)

        # Bottom splitter (AI Analysis and Cyber Assistant)
        bottom_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left side - AI Analysis and Report Generation
        analysis_widget = QWidget()
        analysis_layout = QVBoxLayout(analysis_widget)
        analysis_group = QGroupBox("AI Analysis & Reporting")
        analysis_inner = QVBoxLayout()

        self.ai_analysis_display = QTextEdit()
        self.ai_analysis_display.setReadOnly(True)
        analysis_inner.addWidget(self.ai_analysis_display)

        analysis_controls = QHBoxLayout()
        self.analyze_button = QPushButton("Analyze Vulnerabilities")
        self.analyze_button.clicked.connect(self.analyze_vulnerabilities)
        self.generate_report_button = QPushButton("Generate VAPT Report")
        self.generate_report_button.clicked.connect(self.generate_vapt_report)
        self.generate_report_button.setEnabled(False)  # Disabled until both VA and PT are complete
        self.malware_btn = QPushButton("Malware Analysis")
        self.malware_btn.clicked.connect(self.run_malware_analysis)
        analysis_controls.addWidget(self.analyze_button)
        analysis_controls.addWidget(self.malware_btn)
        analysis_controls.addWidget(self.generate_report_button)
        analysis_inner.addLayout(analysis_controls)

        analysis_group.setLayout(analysis_inner)
        analysis_layout.addWidget(analysis_group)
        bottom_splitter.addWidget(analysis_widget)

        # Right side - Cyber Assistant
        chat_widget = QWidget()
        chat_layout = QVBoxLayout(chat_widget)
        chat_group = QGroupBox("Cyber Assistant")
        chat_inner = QVBoxLayout()

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        chat_inner.addWidget(self.chat_display)

        chat_input_layout = QHBoxLayout()
        self.chat_input = QLineEdit()
        self.chat_input.setPlaceholderText("Ask about security findings...")
        self.chat_input.returnPressed.connect(self.send_chat_message)
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_chat_message)
        chat_input_layout.addWidget(self.chat_input)
        chat_input_layout.addWidget(self.send_button)
        chat_inner.addLayout(chat_input_layout)

        chat_group.setLayout(chat_inner)
        chat_layout.addWidget(chat_group)
        bottom_splitter.addWidget(chat_widget)

        # Add bottom splitter to main layout
        main_layout.addWidget(bottom_splitter)

    def browse_output(self):
        """Open directory browser dialog"""
        dir_path = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if dir_path:
            self.output_dir_input.setText(dir_path)

    def start_va_scan(self):
        """Start vulnerability assessment scan"""
        self.target_url = self.target_url_input.text().strip()
        self.output_dir = self.output_dir_input.text().strip()
        
        if not self.target_url:
            QMessageBox.warning(self, "Input Error", "Please enter a target URL")
            return
            
        if not self.output_dir:
            QMessageBox.warning(self, "Input Error", "Please select an output directory")
            return

        # Show VA progress bar
        self.va_progress.setValue(0)
        self.va_progress.setFormat("")
        self.va_progress.show()
        
        # Disable buttons
        self.start_va_button.setEnabled(False)
        self.start_pt_button.setEnabled(False)

        # Create VA scan worker
        self.va_worker = VAScanWorker(self.target_url, self.output_dir)
        self.va_worker.progress.connect(self.update_va_progress)
        self.va_worker.finished.connect(self.handle_scan_results)
        self.va_worker.start()

    def start_pentest(self):
        """Start penetration testing"""
        if not self.target_url:
            QMessageBox.warning(self, "Input Error", "Please run a VA scan first or enter a target URL")
            return

        # Show PT progress bar
        self.pt_progress.setValue(0)
        self.pt_progress.setFormat("")
        self.pt_progress.show()
        
        # Show loading indicator
        self.loading.show_on_parent()
        
        # Disable buttons
        self.start_pt_button.setEnabled(False)
        self.start_va_button.setEnabled(False)

        # Create pentest worker
        self.pt_worker = PentestWorker(self.target_url, self.output_dir)
        self.pt_worker.progress.connect(self.update_pt_progress)
        self.pt_worker.finished.connect(self.handle_pt_results)
        self.pt_worker.start()

    def stop_scan(self):
        """Stop the current vulnerability assessment scan"""
        if hasattr(self, 'va_worker'):
            self.va_worker.stop()
            self.loading.hide()
            self.start_va_button.setEnabled(True)
            self.start_pt_button.setEnabled(True)

    def stop_pentest(self):
        """Stop the current penetration test"""
        if hasattr(self, 'pt_worker'):
            self.pt_worker.stop()
            self.loading.hide()
            self.start_pt_button.setEnabled(True)
            self.start_va_button.setEnabled(True)

    def update_pt_progress(self, message, percentage):
        """Update penetration test progress"""
        self.pt_progress.setValue(percentage)
        self.pt_progress.setFormat(f"{message} ({percentage}%)")
        self.pt_progress.show()

    def update_va_progress(self, message, percentage):
        """Update vulnerability assessment progress"""
        self.va_progress.setValue(percentage)
        self.va_progress.setFormat(f"{message} ({percentage}%)")
        self.va_progress.show()

    def handle_scan_results(self, result):
        """Handle vulnerability assessment scan results"""
        self.va_progress.hide()
        self.loading.hide()
        if result["status"] == "success":
            self.vulnerabilities = result["vulnerabilities"]
            self.display_vulnerabilities(self.vulnerabilities)
            self.va_complete = True
            self.start_pt_button.setEnabled(True)  # Enable PT after VA
            self.pt_ready_vulnerabilities = self.vulnerabilities
            self.check_report_button_state()
            QMessageBox.information(self, "Scan Complete", "Vulnerability assessment completed successfully!")
        else:
            self.start_va_button.setEnabled(True)
            QMessageBox.warning(self, "Scan Error", f"Error during scan: {result.get('message', 'Unknown error')}")

    def handle_pt_results(self, result):
        """Handle penetration testing results"""
        self.pt_progress.hide()
        self.loading.hide()
        if result["status"] == "success":
            self.pt_results = result["results"]
            self.display_pt_results(self.pt_results)
            self.pt_complete = True
            self.check_report_button_state()
            QMessageBox.information(self, "Pentest Complete", "Penetration testing completed successfully!")
        else:
            self.start_pt_button.setEnabled(True)
            QMessageBox.warning(self, "Pentest Error", f"Error during pentest: {result.get('message', 'Unknown error')}")

    def check_report_button_state(self):
        """Enable report button if both VA and PT are complete"""
        self.generate_report_button.setEnabled(self.va_complete and self.pt_complete)

    def generate_vapt_report(self):
        """Generate comprehensive VAPT report (PDF only, using Python-based generator)"""
        try:
            self.loading.show_on_parent()

            # Prepare report data
            va_results = self.vulnerabilities if hasattr(self, 'vulnerabilities') else []
            pt_results = self.pt_results if hasattr(self, 'pt_results') else {}
            output_dir = self.output_dir or os.getcwd()

            # Use AI model for executive summary and recommendations (optional, can be added to va_results)
            # (If you want to inject AI summary/recommendations, do it here)

            # Use the Python-based PDF generator
            pdf_generator = VAPTReportGenerator(output_dir)
            pdf_file = pdf_generator.generate_report(self.target_url, va_results, pt_results)

            self.loading.hide()
            if pdf_file and os.path.exists(pdf_file):
                QMessageBox.information(
                    self,
                    "Report Generated",
                    f"VAPT PDF Report has been generated successfully!\nLocation: {pdf_file}"
                )
            else:
                QMessageBox.warning(
                    self,
                    "PDF Generation Error",
                    f"PDF report could not be created. Please check for errors in the report generator."
                )
        except Exception as e:
            self.loading.hide()
            QMessageBox.warning(
                self,
                "Report Generation Error",
                f"Error generating VAPT report: {str(e)}"
            )

    def display_vulnerabilities(self, vulns):
        """Display vulnerabilities in the table"""
        self.vuln_table.setRowCount(0)
        severity_colors = {
            'critical': QColor(255, 0, 0),    # Red
            'high': QColor(255, 165, 0),      # Orange
            'medium': QColor(255, 255, 0),    # Yellow
            'low': QColor(0, 255, 0),         # Green
            'info': QColor(135, 206, 235)     # Sky Blue
        }
        
        for vuln in vulns:
            row = self.vuln_table.rowCount()
            self.vuln_table.insertRow(row)
            severity = vuln.get('severity', '').lower()
            color = severity_colors.get(severity, QColor(255, 255, 255))  # White for unknown severity
            
            items = [
                QTableWidgetItem(vuln.get('name', '')),
                QTableWidgetItem(vuln.get('severity', '')),
                QTableWidgetItem(vuln.get('owasp', '')),
                QTableWidgetItem(vuln.get('description', '')),
                QTableWidgetItem(vuln.get('url', ''))
            ]
            
            for item in items:
                item.setBackground(QBrush(color))
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            
            for col, item in enumerate(items):
                self.vuln_table.setItem(row, col, item)
        
        self.vuln_table.resizeColumnsToContents()
        header = self.vuln_table.horizontalHeader()
        for i in range(self.vuln_table.columnCount()):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
        self.vuln_table.setVisible(True)

    def display_pt_results(self, results):
        """Display penetration testing results"""
        self.pt_results_display.clear()
        # Reconnaissance
        if "recon" in results:
            self.pt_results_display.append("=== Reconnaissance Results ===\n")
            recon = results["recon"]
            if isinstance(recon, dict):
                for key, value in recon.items():
                    self.pt_results_display.append(f"{key.capitalize()}:")
                    if isinstance(value, dict):
                        for k, v in value.items():
                            self.pt_results_display.append(f"  {k}: {v}")
                    elif isinstance(value, list):
                        for item in value:
                            self.pt_results_display.append(f"  {item}")
                    else:
                        self.pt_results_display.append(f"  {value}")
                    self.pt_results_display.append("")
        # Other phases
        for key in ["ports", "directories", "xss", "sqli", "headers", "waf"]:
            if key in results:
                self.pt_results_display.append(f"=== {key.capitalize()} Results ===\n")
                value = results[key]
                if isinstance(value, dict):
                    for k, v in value.items():
                        self.pt_results_display.append(f"  {k}: {v}")
                elif isinstance(value, list):
                    for item in value:
                        self.pt_results_display.append(f"  {item}")
                else:
                    self.pt_results_display.append(f"  {value}")
                self.pt_results_display.append("")
        # Show the full JSON for debugging if nothing else
        if not self.pt_results_display.toPlainText().strip():
            self.pt_results_display.setPlainText(json.dumps(results, indent=2))

    def analyze_vulnerabilities(self):
        """Analyze vulnerabilities using AI"""
        if not self.vulnerabilities:
            QMessageBox.warning(self, "No Data", "No vulnerabilities to analyze.")
            return

        max_default = 20
        total_vulns = len(self.vulnerabilities)
        # Sort vulnerabilities by severity (Critical > High > Medium > Low > Info)
        severity_order = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4, 'info': 5}
        sorted_vulns = sorted(self.vulnerabilities, key=lambda v: severity_order.get(v.get('severity', '').lower(), 99))
        vulns_to_analyze = sorted_vulns
        extra_vulns = 0
        if total_vulns > max_default:
            # Prompt user for how many to analyze
            num, ok = QInputDialog.getInt(self, "Too Many Vulnerabilities", f"There are {total_vulns} vulnerabilities. How many do you want to analyze? (max {total_vulns})", max_default, 1, total_vulns, 1)
            if not ok:
                self.ai_analysis_display.setPlainText("Analysis cancelled by user.")
                return
            vulns_to_analyze = sorted_vulns[:num]
            extra_vulns = total_vulns - num

        self.ai_analysis_display.clear()
        self.ai_analysis_display.setPlainText("Analyzing vulnerabilities...")
        QApplication.processEvents()

        # Show loading indicator
        self.loading.show_on_parent()

        try:
            # Analyze vulnerabilities
            analysis_results = self.chat_model.analyze_scan_results(vulns_to_analyze, {
                "target_url": self.target_url,
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_vulnerabilities": len(vulns_to_analyze)
            })

            if analysis_results["status"] == "success":
                # Format the analysis results
                analysis = analysis_results['analysis']
                formatted_analysis = f"""
## Vulnerability Analysis Summary for {self.target_url}

### Overall Security Assessment
{analysis.get('summary', 'No summary available')}

### Critical Findings
{chr(10).join('- ' + finding for finding in analysis.get('critical_findings', ['No critical findings available']))}

### Risk Level
{analysis.get('risk_level', 'Unknown')} (Score: {analysis.get('risk_score', 0)}/100)

### Recommendations
{chr(10).join('- ' + (rec.get('mitigation', str(rec))) for rec in analysis.get('recommendations', ['No recommendations available']))}

### AI Insights
{chr(10).join('- ' + insight for insight in analysis.get('ai_insights', ['No AI insights available']))}

### Additional Notes
{analysis.get('additional_notes', 'No additional notes')}
"""
                if extra_vulns > 0:
                    formatted_analysis += f"\n\n**Note:** {extra_vulns} more vulnerabilities were not included in this analysis due to space limits."
                self.ai_analysis_display.setMarkdown(formatted_analysis)
            else:
                raise Exception(analysis_results.get("message", "Unknown error during analysis"))
        except Exception as e:
            self.loading.hide()
            QMessageBox.warning(self, "Analysis Error", f"Error during analysis: {str(e)}")
        self.loading.hide()

    def send_chat_message(self):
        """Handle chat message sending and response"""
        user_message = self.chat_input.text().strip()
        if not user_message:
            return
        # Clear input
        self.chat_input.clear()
        # Display user message
        self.chat_display.append(f"\nYou: {user_message}")
        QApplication.processEvents()
        # Disable chat input and send button
        self.chat_input.setEnabled(False)
        self.send_button.setEnabled(False)
        # Show loading animation/message in chat
        loading_msg = "\n<span style='color: #888;'>Cyber Assistant is typing... <b>🤖</b></span>"
        self.chat_display.append(loading_msg)
        QApplication.processEvents()
        try:
            # Check if model is initialized
            if self.chat_model is None:
                raise Exception("AI model is not properly initialized")
            # Prepare context
            context = {
                "target_url": self.target_url if self.target_url else "No target specified",
                "findings": []
            }
            if hasattr(self, 'vulnerabilities') and self.vulnerabilities:
                # Add vulnerability findings to context
                context["findings"] = self.vulnerabilities
            # Get AI response using chat method
            response = self.chat_model.chat(user_message, context)
            # Remove loading message
            self._remove_last_loading_message()
            if response["status"] == "success":
                self.chat_display.append(f"\nCyber Assistant: {response['response']}")
            else:
                self.chat_display.append(f"\n<span style='color: red;'><b>Cyber Assistant Error:</b> {response.get('message', 'Unknown error')}</span>")
        except Exception as e:
            self._remove_last_loading_message()
            self.chat_display.append(f"\n<span style='color: red;'><b>Cyber Assistant Error:</b> {str(e)}</span>")
        # Re-enable chat input and send button
        self.chat_input.setEnabled(True)
        self.send_button.setEnabled(True)
        QApplication.processEvents()

    def _remove_last_loading_message(self):
        """Remove the last loading message from the chat display (if present)."""
        # Get current chat text
        chat_html = self.chat_display.toHtml()
        # Remove the last loading message (by known HTML)
        loading_html = "<span style=\'color: #888;\'>Cyber Assistant is typing... <b>🤖</b></span>"
        if loading_html in chat_html:
            chat_html = chat_html.replace(loading_html, "")
            self.chat_display.setHtml(chat_html)

    def run_malware_analysis(self):
        # Launch the full-featured Malware Analysis GUI (vt_gui.py) as a separate process
        import subprocess
        import sys
        import os
        vt_gui_path = os.path.join(os.path.dirname(__file__), "vt_gui.py")
        python_exe = sys.executable
        try:
            subprocess.Popen([python_exe, vt_gui_path])
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to launch Malware Analysis GUI:\n{e}")
        # If you want to keep the old backend scan, uncomment below:
        # targets = []
        # url_col = self.vuln_table.columnCount() - 1
        # for row in range(self.vuln_table.rowCount()):
        #     url_item = self.vuln_table.item(row, url_col)
        #     if url_item:
        #         url = url_item.text().strip()
        #         if url and url not in targets:
        #             targets.append(url)
        # if not targets:
        #     QMessageBox.information(self, "No Targets", "No URLs found for malware analysis.")
        #     return
        # self.statusBar().showMessage("Running malware analysis...")
        # QApplication.processEvents()
        # results = scan_targets_sync(targets)
        # self.malware_results = results
        # self.show_malware_results(results)
        # self.statusBar().showMessage("Malware analysis completed.")

    def show_malware_results(self, results):
        dlg = QDialog(self)
        dlg.setWindowTitle("Malware Analysis Results")
        layout = QVBoxLayout()
        for idx, result in enumerate(results, 1):
            text = f"{idx}. Target: {result.get('target', 'N/A')}\n"
            if result.get('error'):
                text += f"Error: {result['error']}\n"
            else:
                stats = result.get('stats', {})
                text += f"Malicious: {stats.get('malicious', 0)}, Suspicious: {stats.get('suspicious', 0)}, Harmless: {stats.get('harmless', 0)}\n"
                detections = result.get('last_analysis_results', {})
                for vendor, det in list(detections.items())[:10]:
                    text += f"  - {vendor}: {det.get('category', 'unknown').title()} - {det.get('result', 'N/A')}\n"
            label = QLabel(text)
            label.setStyleSheet("font-family: Consolas, monospace;")
            layout.addWidget(label)
        btn = QPushButton("Close")
        btn.clicked.connect(dlg.accept)
        layout.addWidget(btn)
        dlg.setLayout(layout)
        dlg.exec()

def main():
    app = QApplication(sys.argv)
    window = AutoVAPT()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main() 