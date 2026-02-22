import sys
import os
import time
import base64
import hashlib
import json
import asyncio
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
import vt
from vt.error import APIError
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout,
    QLineEdit, QPushButton, QLabel, QCheckBox, QTableWidget, QTableWidgetItem,
    QFileDialog, QHBoxLayout, QMessageBox, QProgressBar, QTextEdit,
    QSplitter, QGroupBox, QGridLayout, QFrame, QScrollArea, QComboBox,
    QHeaderView, QSpacerItem, QSizePolicy
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QFont, QPalette, QPixmap, QIcon

# Load environment variables
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")
from reportlab.lib.pagesizes import letter, A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.units import inch


def vt_url_id(url: str) -> str:
    """Generate VirusTotal URL ID"""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def calculate_file_hash(file_path: str) -> dict:
    """Calculate multiple hashes for a file"""
    hashes = {'md5': hashlib.md5(), 'sha1': hashlib.sha1(), 'sha256': hashlib.sha256()}
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            for hash_obj in hashes.values():
                hash_obj.update(chunk)
    
    return {name: hash_obj.hexdigest() for name, hash_obj in hashes.items()}


class ScanThread(QThread):
    """Background thread for scanning operations"""
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    scan_completed = pyqtSignal(dict)
    scan_failed = pyqtSignal(str)

    def __init__(self, api_key, object_type, query, file_path=None):
        super().__init__()
        self.api_key = api_key
        self.object_type = object_type
        self.query = query
        self.file_path = file_path

    def run(self):
        """Run the scanning operation in a separate thread with proper async handling"""
        try:
            # Create new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                # Run the async scan operation
                results = loop.run_until_complete(self._run_async_scan())
                self.progress_updated.emit(100)
                self.status_updated.emit("Scan completed successfully!")
                self.scan_completed.emit(results)
            finally:
                loop.close()
                
        except Exception as e:
            self.scan_failed.emit(str(e))

    async def _run_async_scan(self):
        """Async scan operation"""
        async with vt.Client(self.api_key) as client:
            self.status_updated.emit("Starting scan...")
            self.progress_updated.emit(10)

            if self.object_type == "file":
                return await self.scan_file(client)
            elif self.object_type == "url":
                return await self.scan_url(client)
            elif self.object_type == "ip_address":
                return await self.scan_ip(client)
            elif self.object_type == "domain":
                return await self.scan_domain(client)

    async def scan_file(self, client):
        if os.path.exists(self.query):
            # Upload and scan new file
            self.status_updated.emit("Uploading file...")
            self.progress_updated.emit(20)
            
            with open(self.query, "rb") as f:
                analysis = await client.scan_file_async(f)
    
            self.status_updated.emit("Waiting for analysis...")
            self.progress_updated.emit(40)
    
            # Wait for analysis completion
            analysis_result = None
            for i in range(60):  # Increased timeout to 5 minutes
                try:
                    analysis_result = await client.get_object_async(f"/analyses/{analysis.id}")
                    if hasattr(analysis_result, 'status') and analysis_result.status == "completed":
                        break
                    self.progress_updated.emit(40 + (i * 1))
                    await asyncio.sleep(5)
                except Exception as e:
                    if i > 10:  # After 50 seconds, show the error
                        self.status_updated.emit(f"Still processing... ({i*5}s)")
                    await asyncio.sleep(5)
    
            if not analysis_result or not hasattr(analysis_result, 'status') or analysis_result.status != "completed":
                raise Exception("Analysis timeout - file may be too large or VirusTotal is busy. Try again later.")
    
            # Get the file hash from analysis metadata
            if hasattr(analysis_result, 'meta') and 'file_info' in analysis_result.meta:
                file_hash = analysis_result.meta['file_info']['sha256']
            else:
                # Fallback: calculate hash locally
                hashes = calculate_file_hash(self.query)
                file_hash = hashes['sha256']
            
            # Now get the file object
            obj = await client.get_object_async(f"/files/{file_hash}")

        self.progress_updated.emit(90)
        return self.format_file_results(obj)

    async def scan_url(self, client):
        self.status_updated.emit("Submitting URL for analysis...")
        analysis = await client.scan_url_async(self.query)
        self.progress_updated.emit(30)

        url_id = vt_url_id(self.query)
        self.status_updated.emit("Retrieving analysis results...")
        
        for i in range(20):
            try:
                obj = await client.get_object_async(f"/urls/{url_id}")
                break
            except APIError as e:
                if "NotFoundError" in str(e):
                    self.progress_updated.emit(30 + (i * 3))
                    await asyncio.sleep(3)
                else:
                    raise
        
        self.progress_updated.emit(90)
        return self.format_url_results(obj)

    async def scan_ip(self, client):
        self.status_updated.emit("Analyzing IP address...")
        obj = await client.get_object_async(f"/ip_addresses/{self.query}")
        self.progress_updated.emit(90)
        return self.format_ip_results(obj)

    async def scan_domain(self, client):
        self.status_updated.emit("Analyzing domain...")
        obj = await client.get_object_async(f"/domains/{self.query}")
        self.progress_updated.emit(90)
        return self.format_domain_results(obj)

    def format_file_results(self, obj):
        results = {
            'type': 'file',
            'target': getattr(obj, 'meaningful_name', 'Unknown'),
            'md5': getattr(obj, 'md5', 'N/A'),
            'sha1': getattr(obj, 'sha1', 'N/A'),
            'sha256': getattr(obj, 'sha256', 'N/A'),
            'size': getattr(obj, 'size', 'N/A'),
            'file_type': getattr(obj, 'type_description', 'N/A'),
            'first_submission_date': getattr(obj, 'first_submission_date', None),
            'last_analysis_date': getattr(obj, 'last_analysis_date', None),
            'last_analysis_results': getattr(obj, 'last_analysis_results', {}),
            'stats': getattr(obj, 'last_analysis_stats', {}),
            'names': getattr(obj, 'names', []),
            'signature_info': getattr(obj, 'signature_info', {}),
        }
        return results

    def format_url_results(self, obj):
        results = {
            'type': 'url',
            'target': getattr(obj, 'url', self.query),
            'last_analysis_date': getattr(obj, 'last_analysis_date', None),
            'last_analysis_results': getattr(obj, 'last_analysis_results', {}),
            'stats': getattr(obj, 'last_analysis_stats', {}),
            'categories': getattr(obj, 'categories', {}),
            'reputation': getattr(obj, 'reputation', 0),
        }
        return results

    def format_ip_results(self, obj):
        results = {
            'type': 'ip_address',
            'target': self.query,
            'country': getattr(obj, 'country', 'N/A'),
            'as_owner': getattr(obj, 'as_owner', 'N/A'),
            'last_analysis_date': getattr(obj, 'last_analysis_date', None),
            'last_analysis_results': getattr(obj, 'last_analysis_results', {}),
            'stats': getattr(obj, 'last_analysis_stats', {}),
            'reputation': getattr(obj, 'reputation', 0),
        }
        return results

    def format_domain_results(self, obj):
        results = {
            'type': 'domain',
            'target': self.query,
            'registrar': getattr(obj, 'registrar', 'N/A'),
            'creation_date': getattr(obj, 'creation_date', None),
            'last_analysis_date': getattr(obj, 'last_analysis_date', None),
            'last_analysis_results': getattr(obj, 'last_analysis_results', {}),
            'stats': getattr(obj, 'last_analysis_stats', {}),
            'reputation': getattr(obj, 'reputation', 0),
            'categories': getattr(obj, 'categories', {}),
        }
        return results


class APITestThread(QThread):
    """Thread for testing API connection"""
    connection_success = pyqtSignal()
    connection_failed = pyqtSignal(str)
    
    def __init__(self, api_key):
        super().__init__()
        self.api_key = api_key
    
    def run(self):
        try:
            # Create new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                loop.run_until_complete(self._test_connection())
                self.connection_success.emit()
            finally:
                loop.close()
                
        except Exception as e:
            self.connection_failed.emit(str(e))
    
    async def _test_connection(self):
        """Test API connection asynchronously"""
        async with vt.Client(self.api_key) as client:
            try:
                # Try to get quota information to verify the API key
                await client.get_object_async("/users/current")
            except APIError as e:
                if "InvalidArgumentError" in str(e) or "AuthenticationRequiredError" in str(e):
                    raise Exception("Invalid API key provided")
                else:
                    # API key might be valid but quota endpoint not accessible
                    pass


class VTTab(QWidget):
    def __init__(self, object_type: str, api_key: str):
        super().__init__()
        self.object_type = object_type
        self.api_key = api_key
        self.file_path = None
        self.scan_results = None
        self.all_results = {}  # Initialize this early
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(5, 5, 5, 5)

        # Input Section
        input_group = QGroupBox(f"Input: {self.object_type.replace('_', ' ').title()}")
        input_group.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        input_layout = QVBoxLayout()

        # Input controls
        if self.object_type == "file":
            file_layout = QHBoxLayout()
            self.input_box = QLineEdit()
            self.input_box.setPlaceholderText("Select a file or enter file hash (MD5/SHA1/SHA256)")
            self.input_box.setMinimumHeight(35)
            
            self.file_btn = QPushButton("Browse File")
            self.file_btn.setMinimumHeight(35)
            self.file_btn.clicked.connect(self.upload_file)
            
            file_layout.addWidget(self.input_box, 3)
            file_layout.addWidget(self.file_btn, 1)
            input_layout.addLayout(file_layout)
        else:
            self.input_box = QLineEdit()
            placeholders = {
                "url": "Enter URL (e.g., https://example.com)",
                "ip_address": "Enter IP address (e.g., 8.8.8.8)",
                "domain": "Enter domain (e.g., example.com)"
            }
            self.input_box.setPlaceholderText(placeholders.get(self.object_type, f"Enter {self.object_type}"))
            self.input_box.setMinimumHeight(35)
            input_layout.addWidget(self.input_box)

        # Options
        options_layout = QHBoxLayout()
        self.include_details = QCheckBox("Include detailed information")
        self.include_details.setChecked(True)
        
        options_layout.addWidget(self.include_details)
        options_layout.addStretch()
        
        input_layout.addLayout(options_layout)

        # Scan button
        self.submit_btn = QPushButton("Start Scan")
        self.submit_btn.setMinimumHeight(40)
        self.submit_btn.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        self.submit_btn.clicked.connect(self.scan)
        input_layout.addWidget(self.submit_btn)

        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)

        # Progress Section
        progress_group = QGroupBox("Scan Progress")
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumHeight(16)
        self.status_label = QLabel("Ready to scan")
        self.status_label.setStyleSheet("color: #666; font-style: italic;")
        
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        progress_group.setLayout(progress_layout)
        main_layout.addWidget(progress_group)

        # Results Section
        results_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Summary Panel
        summary_group = QGroupBox("Analysis Summary")
        summary_group.setStyleSheet("""
            QGroupBox {
                font-size: 13px;
                font-weight: bold;
                border: 1px solid #ccc;
                border-radius: 10px;
                margin-top: 15px;
                padding-top: 20px;
                background-color: #f8f9ff;
            }
        """)
        self.summary_text = QTextEdit()
        self.summary_text.setMinimumHeight(400)
        self.summary_text.setReadOnly(True)
        self.summary_text.setStyleSheet("""
            QTextEdit {
                border: 2px solid #ddd;
                border-radius: 8px;
                padding: 15px;
                font-size: 13px;
                background-color: white;
                line-height: 1.4;
            }
        """)
        summary_layout = QVBoxLayout()
        summary_layout.addWidget(self.summary_text)
        summary_group.setLayout(summary_layout)

        # Results Table
        table_group = QGroupBox("Detection Results")
        table_group.setStyleSheet("""
            QGroupBox {
                font-size: 13px;
                font-weight: bold;
                border: 1px solid #ccc;
                border-radius: 10px;
                margin-top: 15px;
                padding-top: 20px;
                background-color: #fff8f8;
            }
        """)
        table_layout = QVBoxLayout()
        
        # Filter controls
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Detection Results:"))
        filter_layout.addStretch()
        filter_layout.addWidget(QLabel("Filter by:"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All Results", "Malicious Only", "Clean Only", "Suspicious Only"])
        self.filter_combo.currentTextChanged.connect(self.filter_results)
        filter_layout.addWidget(self.filter_combo)
        filter_layout.addStretch()
        
        table_layout.addLayout(filter_layout)
        
        # Create table - ONLY ONCE
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Vendor", "Category", "Result", "Details"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setMinimumHeight(400)
        self.table.setStyleSheet("""
            QTableWidget {
                gridline-color: #e0e0e0;
                background-color: white;
                alternate-background-color: #f8f9fa;
                border: 2px solid #ddd;
                border-radius: 8px;
                font-size: 12px;
            }
            QTableWidget::item {
                padding: 6px 8px;
                border-bottom: 1px solid #eee;
            }
            QHeaderView::section {
                background-color: #2c3e50;
                color: white;
                padding: 6px 8px;
                border: none;
                font-weight: bold;
                font-size: 12px;
            }
        """)
        
        table_layout.addWidget(self.table)
        table_group.setLayout(table_layout)

        # Add widgets to splitter
        results_splitter.addWidget(summary_group)
        results_splitter.addWidget(table_group)
        results_splitter.setSizes([400, 600])

        main_layout.addWidget(results_splitter)

        # Export Section
        export_group = QGroupBox("Export Results")
        export_layout = QHBoxLayout()

        self.pdf_btn = QPushButton("Export PDF Report")
        self.pdf_btn.setMinimumHeight(35)
        self.pdf_btn.clicked.connect(self.export_pdf)
        self.pdf_btn.setEnabled(False)

        self.json_btn = QPushButton("Export JSON Data")
        self.json_btn.setMinimumHeight(35)
        self.json_btn.clicked.connect(self.export_json)
        self.json_btn.setEnabled(False)

        export_layout.addWidget(self.pdf_btn)
        export_layout.addWidget(self.json_btn)
        export_layout.addStretch()

        export_group.setLayout(export_layout)
        main_layout.addWidget(export_group)

        # Set the main layout
        self.setLayout(main_layout)

    def upload_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "Select File to Scan", 
            "", 
            "All Files (*.*)"
        )
        if file_path:
            self.file_path = file_path
            self.input_box.setText(file_path)
            
            # Show file info
            file_info = Path(file_path)
            size_mb = file_info.stat().st_size / (1024 * 1024)
            self.status_label.setText(f"File selected: {file_info.name} ({size_mb:.2f} MB)")

    def scan(self):
        query = self.input_box.text().strip()
        if not query:
            QMessageBox.warning(self, "Input Required", "Please enter a value to scan.")
            return

        self.submit_btn.setEnabled(False)
        self.pdf_btn.setEnabled(False)
        self.json_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.table.setRowCount(0)
        self.summary_text.clear()

        # Start scan thread
        self.scan_thread = ScanThread(self.api_key, self.object_type, query, self.file_path)
        self.scan_thread.progress_updated.connect(self.progress_bar.setValue)
        self.scan_thread.status_updated.connect(self.status_label.setText)
        self.scan_thread.scan_completed.connect(self.on_scan_completed)
        self.scan_thread.scan_failed.connect(self.on_scan_failed)
        self.scan_thread.start()

    def on_scan_completed(self, results):
        self.scan_results = results
        self.populate_summary(results)
        
        # Store the results and populate table
        analysis_results = results.get('last_analysis_results', {})
        print(f"DEBUG: Got {len(analysis_results)} analysis results")  # Debug line
        
        if analysis_results:
            self.all_results = analysis_results
            self.populate_table()
        else:
            print("DEBUG: No analysis results found")  # Debug line
            # Show a message in the table
            self.table.setRowCount(1)
            self.table.setItem(0, 0, QTableWidgetItem("No detection results"))
            self.table.setItem(0, 1, QTableWidgetItem("-"))
            self.table.setItem(0, 2, QTableWidgetItem("-"))
            self.table.setItem(0, 3, QTableWidgetItem("-"))
        
        self.submit_btn.setEnabled(True)
        self.pdf_btn.setEnabled(True)
        self.json_btn.setEnabled(True)

    def on_scan_failed(self, error_message):
        QMessageBox.critical(self, "Scan Failed", f"An error occurred during scanning:\n\n{error_message}")
        self.submit_btn.setEnabled(True)
        self.status_label.setText("Scan failed")
        self.progress_bar.setValue(0)

    def populate_summary(self, results):
        """Populate the summary panel with key information"""
        summary_html = f"""
        <div style="font-family: Arial; font-size: 12px;">
            <h3 style="color: #2c3e50; margin-bottom: 10px;">Analysis Summary</h3>
            <p><strong>Target:</strong> {results.get('target', 'N/A')}</p>
            <p><strong>Type:</strong> {results.get('type', 'N/A').replace('_', ' ').title()}</p>
        """
        
        if 'stats' in results and results['stats']:
            stats = results['stats']
            total = sum(stats.values())
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            clean = stats.get('harmless', 0)
            
            summary_html += f"""
            <p><strong>Detection Ratio:</strong> {malicious + suspicious}/{total}</p>
            <p><strong>Malicious:</strong> {malicious}</p>
            <p><strong>Suspicious:</strong> {suspicious}</p>
            <p><strong>Clean:</strong> {clean}</p>
            """

        if results.get('type') == 'file':
            summary_html += f"""
            <p><strong>MD5:</strong> {results.get('md5', 'N/A')}</p>
            <p><strong>SHA256:</strong> {results.get('sha256', 'N/A')}</p>
            <p><strong>Size:</strong> {results.get('size', 'N/A')} bytes</p>
            <p><strong>File Type:</strong> {results.get('file_type', 'N/A')}</p>
            """

        if results.get('last_analysis_date'):
            last_analysis = results['last_analysis_date']
            if isinstance(last_analysis, datetime):
                analysis_date = last_analysis
            elif isinstance(last_analysis, (int, float)):
                analysis_date = datetime.fromtimestamp(last_analysis)
            else:
                analysis_date = None
    
            if analysis_date:
                summary_html += f"<p><strong>Last Analysis:</strong> {analysis_date.strftime('%Y-%m-%d %H:%M:%S')}</p>"
        
        summary_html += "</div>"
        self.summary_text.setHtml(summary_html)

    def populate_table(self):
        """Populate the results table - FIXED VERSION"""
        print(f"DEBUG: populate_table called with {len(self.all_results)} results")  # Debug line
        
        if not self.all_results:
            self.table.setRowCount(1)
            self.table.setItem(0, 0, QTableWidgetItem("No results available"))
            self.table.setItem(0, 1, QTableWidgetItem("-"))
            self.table.setItem(0, 2, QTableWidgetItem("-"))
            self.table.setItem(0, 3, QTableWidgetItem("-"))
            return

        # Apply current filter
        self.filter_results()

    def filter_results(self):
        """Filter table results based on selection - FIXED VERSION"""
        if not self.all_results:
            print("DEBUG: No all_results to filter")  # Debug line
            return
            
        print(f"DEBUG: Filtering {len(self.all_results)} results")  # Debug line

        filter_text = self.filter_combo.currentText()
        results = self.all_results.copy()

        if filter_text == "Malicious Only":
            filtered = {k: v for k, v in results.items() if v.get("category") == "malicious"}
        elif filter_text == "Clean Only":
            filtered = {k: v for k, v in results.items() if v.get("category") == "harmless"}
        elif filter_text == "Suspicious Only":
            filtered = {k: v for k, v in results.items() if v.get("category") == "suspicious"}
        else:
            filtered = results

        print(f"DEBUG: After filtering: {len(filtered)} results")  # Debug line

        # Clear and populate table
        self.table.setRowCount(len(filtered))

        if not filtered:
            self.table.setRowCount(1)
            self.table.setItem(0, 0, QTableWidgetItem("No results match filter"))
            self.table.setItem(0, 1, QTableWidgetItem("-"))
            self.table.setItem(0, 2, QTableWidgetItem("-"))
            self.table.setItem(0, 3, QTableWidgetItem("-"))
            return

        for row, (vendor, result) in enumerate(filtered.items()):
            print(f"DEBUG: Adding row {row}: {vendor} - {result.get('category', 'unknown')}")  # Debug line
            
            # Vendor
            vendor_item = QTableWidgetItem(str(vendor))
            vendor_item.setFont(QFont("Arial", 10, QFont.Weight.Bold))
            self.table.setItem(row, 0, vendor_item)

            # Category
            category = result.get("category", "unknown")
            category_item = QTableWidgetItem(category.title())

            # Color coding
            if category == "malicious":
                category_item.setBackground(QColor("#ffebee"))
                category_item.setForeground(QColor("#c62828"))
            elif category == "harmless":
                category_item.setBackground(QColor("#e8f5e8"))
                category_item.setForeground(QColor("#2e7d32"))
            elif category == "suspicious":
                category_item.setBackground(QColor("#fff3e0"))
                category_item.setForeground(QColor("#ef6c00"))
            else:
                category_item.setBackground(QColor("#f5f5f5"))
                category_item.setForeground(QColor("#666"))

            self.table.setItem(row, 1, category_item)

            # Result
            result_text = str(result.get("result", "Unknown"))
            result_item = QTableWidgetItem(result_text)
            self.table.setItem(row, 2, result_item)

            # Details
            details = result.get("method", "N/A")
            if result.get("engine_update"):
                details += f" (Updated: {result.get('engine_update')})"
            details_item = QTableWidgetItem(details)
            self.table.setItem(row, 3, details_item)

        print(f"DEBUG: Table populated with {self.table.rowCount()} rows")  # Debug line

    def export_pdf(self):
        """Export detailed PDF report"""
        if not self.scan_results:
            QMessageBox.warning(self, "No Data", "No scan results available to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, 
            "Save PDF Report", 
            f"VirusTotal_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf", 
            "PDF Files (*.pdf)"
        )
        
        if not file_path:
            return

        try:
            doc = SimpleDocTemplate(file_path, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []

            # Title
            title = Paragraph("VirusTotal Analysis Report", styles['Title'])
            story.append(title)
            story.append(Spacer(1, 20))

            # Summary Section
            summary_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                textColor=colors.darkblue,
                spaceAfter=10
            )
            
            story.append(Paragraph("Executive Summary", summary_style))
            
            summary_data = [
                ["Target", self.scan_results.get('target', 'N/A')],
                ["Analysis Type", self.scan_results.get('type', 'N/A').replace('_', ' ').title()],
                ["Report Generated", datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            ]

            if 'stats' in self.scan_results and self.scan_results['stats']:
                stats = self.scan_results['stats']
                total = sum(stats.values())
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                
                summary_data.extend([
                    ["Detection Ratio", f"{malicious + suspicious}/{total}"],
                    ["Malicious Detections", str(malicious)],
                    ["Suspicious Detections", str(suspicious)],
                    ["Clean Detections", str(stats.get('harmless', 0))],
                ])

            if self.scan_results.get('type') == 'file':
                summary_data.extend([
                    ["MD5 Hash", self.scan_results.get('md5', 'N/A')],
                    ["SHA1 Hash", self.scan_results.get('sha1', 'N/A')],
                    ["SHA256 Hash", self.scan_results.get('sha256', 'N/A')],
                    ["File Size", f"{self.scan_results.get('size', 'N/A')} bytes"],
                    ["File Type", self.scan_results.get('file_type', 'N/A')],
                ])

            summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(summary_table)
            story.append(Spacer(1, 20))

            # Detection Results
            story.append(Paragraph("Detailed Detection Results", summary_style))
            
            results = self.scan_results.get('last_analysis_results', {})
            if results:
                table_data = [["Vendor", "Category", "Result"]]
                
                for vendor, result in results.items():
                    table_data.append([
                        vendor,
                        result.get('category', 'Unknown').title(),
                        str(result.get('result', 'Unknown'))
                    ])

                results_table = Table(table_data, colWidths=[1.5*inch, 1*inch, 2*inch, 1.5*inch])
                results_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(results_table)

            doc.build(story)
            QMessageBox.information(self, "Export Successful", f"PDF report saved to:\n{file_path}")

        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Failed to generate PDF report:\n{str(e)}")

    def export_json(self):
        """Export results as JSON"""
        if not self.scan_results:
            QMessageBox.warning(self, "No Data", "No scan results available to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, 
            "Save JSON Report", 
            f"VirusTotal_Results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 
            "JSON Files (*.json)"
        )
        
        if not file_path:
            return

        try:
            # Prepare export data
            export_data = {
                "report_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "tool": "VirusTotal GUI Scanner",
                    "version": "2.0"
                },
                "scan_results": self.scan_results
            }

            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            QMessageBox.information(self, "Export Successful", f"JSON report saved to:\n{file_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Failed to export JSON:\n{str(e)}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Malware Analyser v2.0")
        self.resize(1024, 720)
        self.setMinimumSize(1200, 1000)
        self.center_window()
        self.setup_ui()
        self.apply_main_styles()

    def center_window(self):
        """Center the window on screen"""
        screen = QApplication.primaryScreen().geometry()
        size = self.geometry()
        self.move(
            (screen.width() - size.width()) // 2,
            (screen.height() - size.height()) // 2
        )

    def setup_ui(self):
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout()
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(8, 8, 8, 8)

        # Header Section
        header_frame = QFrame()
        header_frame.setFrameStyle(QFrame.Shape.Box)
        header_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #3498db, stop:1 #2980b9);
                border-radius: 10px;
                color: white;
                padding: 15px;
            }
        """)
        
        header_layout = QVBoxLayout()
        
        title_label = QLabel("VirusTotal GUI Scanner")
        title_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        title_label.setStyleSheet("color: white; margin: 0; padding: 0;")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        subtitle_label = QLabel("Professional malware analysis and threat detection")
        subtitle_label.setFont(QFont("Arial", 12))
        subtitle_label.setStyleSheet("color: #ecf0f1; margin: 0; padding: 0;")
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        header_layout.addWidget(title_label)
        header_layout.addWidget(subtitle_label)
        header_frame.setLayout(header_layout)
        main_layout.addWidget(header_frame)

        # API Key Section
        api_group = QGroupBox("API Configuration")
        api_group.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        api_layout = QHBoxLayout()
        
        api_layout.addWidget(QLabel("VirusTotal API Key:"))
        
        self.api_key_box = QLineEdit()
        self.api_key_box.setPlaceholderText("Enter your VirusTotal API key here...")
        self.api_key_box.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_box.setMinimumHeight(35)
        if API_KEY:
            self.api_key_box.setText(API_KEY)

        self.api_key_box.setStyleSheet("""
            QLineEdit {
                border: 2px solid #ddd;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 12px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #3498db;
                background-color: #f8f9ff;
            }
        """)
        
        self.show_key_btn = QPushButton("S")
        self.show_key_btn.setMaximumWidth(40)
        self.show_key_btn.setMinimumHeight(35)
        self.show_key_btn.setToolTip("Show/Hide API Key")
        self.show_key_btn.clicked.connect(self.toggle_api_key_visibility)
        
        self.init_button = QPushButton("Connect")
        self.init_button.setMinimumHeight(35)
        self.init_button.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        self.init_button.clicked.connect(self.init_tabs)
        
        api_layout.addWidget(self.api_key_box, 3)
        api_layout.addWidget(self.show_key_btn)
        api_layout.addWidget(self.init_button, 1)
        
        api_group.setLayout(api_layout)
        main_layout.addWidget(api_group)

        # Status Section
        status_layout = QHBoxLayout()
        status_layout.setContentsMargins(8, 3, 8, 3)  # Reduced margins

        self.connection_status = QLabel("Not Connected")
        self.connection_status.setStyleSheet("""
            color: #e67e22; 
            font-weight: bold; 
            padding: 4px 8px;
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            font-size: 11px;
        """)
        self.connection_status.setMaximumHeight(30)  # Limit height

        status_layout.addWidget(self.connection_status)
        status_layout.addStretch()

        # Add status as a simple layout instead of a group box
        main_layout.addLayout(status_layout)

        # Tabs Section
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.TabPosition.North)
        self.tabs.setMovable(True)
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #ddd;
                border-radius: 8px;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #ecf0f1;
                border: 1px solid #bdc3c7;
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                padding: 12px 20px;
                margin-right: 2px;
                font-weight: bold;
                min-width: 120px;
            }
            QTabBar::tab:selected {
                background-color: #3498db;
                color: white;
            }
            QTabBar::tab:hover {
                background-color: #5dade2;
                color: white;
            }
        """)
        
        # Add placeholder message
        placeholder_widget = QWidget()
        placeholder_layout = QVBoxLayout()
        placeholder_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        placeholder_label = QLabel("Please connect with your API key to start scanning")
        placeholder_label.setFont(QFont("Arial", 14))
        placeholder_label.setStyleSheet("color: #7f8c8d; padding: 50px;")
        placeholder_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        api_help_label = QLabel(
            "Don't have an API key? Get one free at: "
            "<a href='https://www.virustotal.com/gui/join-us' style='color: #3498db;'>"
            "https://www.virustotal.com/gui/join-us</a>"
        )
        api_help_label.setFont(QFont("Arial", 11))
        api_help_label.setStyleSheet("color: #95a5a6; padding: 10px;")
        api_help_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        api_help_label.setOpenExternalLinks(True)
        
        placeholder_layout.addWidget(placeholder_label)
        placeholder_layout.addWidget(api_help_label)
        placeholder_widget.setLayout(placeholder_layout)
        
        self.tabs.addTab(placeholder_widget, "Welcome")
        main_layout.addWidget(self.tabs, 1)

        # Footer
        footer_layout = QHBoxLayout()
        footer_layout.addStretch()
        
        footer_label = QLabel("© 2025 Malware Analyser - All rights reserved")
        footer_label.setStyleSheet("color: #95a5a6; font-size: 10px; font-style: italic;")
        footer_layout.addWidget(footer_label)
        footer_layout.addStretch()
        
        main_layout.addLayout(footer_layout)
        central_widget.setLayout(main_layout)

    def apply_main_styles(self):
        """Apply main window styles"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f8f9fa;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #ddd;
                border-radius: 10px;
                margin-top: 12px;
                padding-top: 15px;
                background-color: white;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 10px 0 10px;
                color: #2c3e50;
                font-size: 12px;
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
                min-height: 20px;
            }
            QPushButton:hover {
                background-color: #2980b9;
                transform: translateY(-1px);
            }
            QPushButton:pressed {
                background-color: #21618c;
                transform: translateY(1px);
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
                color: #7f8c8d;
            }
        """)

    def toggle_api_key_visibility(self):
        """Toggle API key visibility"""
        if self.api_key_box.echoMode() == QLineEdit.EchoMode.Password:
            self.api_key_box.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_key_btn.setText("H")
            self.show_key_btn.setToolTip("Hide API Key")
        else:
            self.api_key_box.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_key_btn.setText("S")
            self.show_key_btn.setToolTip("Show API Key")

    def init_tabs(self):
        """Initialize tabs with API client"""
        api_key = self.api_key_box.text().strip()
        if not api_key:
            QMessageBox.warning(self, "API Key Required", "Please enter your VirusTotal API key.")
            return

        try:
            # Test API connection
            self.connection_status.setText("Testing connection...")
            self.connection_status.setStyleSheet("color: #f39c12; font-weight: bold; padding: 8px;")
            QApplication.processEvents()
            
            try:
            # Disable button during testing
                self.init_button.setEnabled(False)

            # Test API connection using thread
                self.api_test_thread = APITestThread(api_key)
                self.api_test_thread.connection_success.connect(lambda: self.on_api_test_success(api_key))
                self.api_test_thread.connection_failed.connect(self.on_api_test_failed)
                self.api_test_thread.start()   
                         
            except APIError as e:
                if "InvalidArgumentError" in str(e) or "AuthenticationRequiredError" in str(e):
                    raise Exception("Invalid API key provided")
                else:
                    # API key might be valid but quota endpoint not accessible
                    self.connection_status.setText("Connected - Limited API access")
                    self.connection_status.setStyleSheet("color: #f39c12; font-weight: bold; padding: 8px;")
            
        except Exception as e:
            error_msg = str(e)
            if "Invalid API key" in error_msg or "AuthenticationRequiredError" in error_msg:
                QMessageBox.critical(
                    self, 
                    "Authentication Failed", 
                    "Invalid API key provided. Please check your API key and try again."
                )
            else:
                QMessageBox.critical(
                    self, 
                    "Connection Error", 
                    f"Failed to connect to VirusTotal:\n\n{error_msg}"
                )
            
            self.connection_status.setText("Connection Failed - Check API key")
            self.connection_status.setStyleSheet("color: #e74c3c; font-weight: bold; padding: 8px;")


    def on_api_test_success(self, api_key):
        """Handle successful API connection"""
        self.connection_status.setText("Connected")
        self.connection_status.setStyleSheet("""
            color: #27ae60; 
            font-weight: bold; 
            padding: 4px 8px;
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 4px;
            font-size: 11px;
        """)
    
    # Clear existing tabs
        self.tabs.clear()
    
    # Add scanning tabs
        tab_configs = [
            ("file", "File Scanner", "Scan files and file hashes"),
            ("url", "URL Scanner", "Scan web URLs"),
            ("ip_address", "IP Scanner", "Analyze IP addresses"),
            ("domain", "Domain Scanner", "Analyze domains")
        ]
    
        for obj_type, tab_title, tooltip in tab_configs:
            tab = VTTab(obj_type, api_key)
            tab_index = self.tabs.addTab(tab, tab_title)
            self.tabs.setTabToolTip(tab_index, tooltip)

        # Set default tab
        self.tabs.setCurrentIndex(0)
        self.init_button.setEnabled(True)

    def on_api_test_failed(self, error_message):
        """Handle failed API connection"""
        if "Invalid API key" in error_message or "Authentication" in error_message:
            QMessageBox.critical(
                self, 
                "Authentication Failed", 
                "Invalid API key provided. Please check your API key and try again."
            )
        else:
            QMessageBox.critical(
                self, 
                "Connection Error", 
                f"Failed to connect to VirusTotal:\n\n{error_message}"
            )
    
        self.connection_status.setText("Connection Failed")
        self.connection_status.setStyleSheet("""
            color: #e74c3c; 
            font-weight: bold; 
            padding: 4px 8px;
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 4px;
            font-size: 11px;
        """)
        self.init_button.setEnabled(True)

def main():
    """Main application entry point"""
    import sys
    if sys.platform.startswith('win'):
        import os
        os.environ['QT_AUTO_SCREEN_SCALE_FACTOR'] = '1'
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Malware Analyser")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("Security Tools")
    
    # Set application icon (if available)
    try:
        app.setWindowIcon(QIcon("icon.png"))
    except:
        pass
    
    # Apply global application style
    app.setStyle("Fusion")
    
    # Set global font
    font = QFont("Arial", 10)
    app.setFont(font)
    
    # Create and show main window
    window = MainWindow()
    window.show()
    
    # Start event loop
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
