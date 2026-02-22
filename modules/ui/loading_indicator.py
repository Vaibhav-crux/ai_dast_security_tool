"""Loading indicator widget for AutoDAST."""

from PyQt6.QtWidgets import QWidget, QLabel, QVBoxLayout
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QMovie
import os

class LoadingIndicator(QWidget):
    """A loading indicator widget that shows a spinning animation."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        # Set up the widget
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setStyleSheet("background-color: rgba(0, 0, 0, 180);")
        
        # Create layout
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # Create label for the spinner
        self.spinner_label = QLabel()
        layout.addWidget(self.spinner_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        # Set up the spinner animation
        spinner_path = os.path.join(os.path.dirname(__file__), "assets", "spinner.gif")
        self.spinner = QMovie(spinner_path)
        self.spinner.setScaledSize(QSize(64, 64))
        self.spinner_label.setMovie(self.spinner)
        
        # Hide initially
        self.hide()
    
    def show_on_parent(self):
        """Show the loading indicator centered on the parent widget."""
        if self.parent():
            # Resize to match parent
            self.resize(self.parent().size())
            # Start the animation
            self.spinner.start()
            # Show the widget
            self.show()
            # Raise to front
            self.raise_()
    
    def hide(self):
        """Hide the loading indicator and stop the animation."""
        self.spinner.stop()
        super().hide() 