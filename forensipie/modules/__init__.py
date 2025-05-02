"""
This package contains all the core analysis modules for the ForensiPie CLI tool.
Each module exposes a callable entry-point function for its respective analysis task.
"""

from .banner_display import show_banner
from .usb_connection import run_usb_device_operations, upload_apk_via_dialog
from .apk_unpack_decompile import analyze_apk_unpack
from .manifest_analysis import analyze_manifest
from .encryption_state_db import analyze_encryption
from .suspicious_api_calls import analyze_suspicious_apis
from .signature_analysis import analyze_signature
from .decide_malicious import decide_maliciousness
from .report_generator import generate_reports
