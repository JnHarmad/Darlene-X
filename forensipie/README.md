# ForensiPie

A comprehensive digital forensics tool for analyzing Android APK files.

## Features

- APK Unpacking and Decompilation
- Manifest Analysis
- Database Encryption Analysis
- Suspicious API Detection
- YARA Signature-based Analysis
- Comprehensive Reporting (HTML, PDF, JSON)

## Installation

```bash
pip install -r requirement.txt
```

## Usage

```bash
python -m forensipie.forensipie_cli /path/to/your.apk
```

## Output

The tool provides detailed analysis in multiple formats:
- Console output with progress indicators
- HTML, PDF, and JSON reports
- Extracted APK contents and decompiled code
