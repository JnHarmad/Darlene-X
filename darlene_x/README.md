# Darlene-X

A comprehensive digital forensics tool for analyzing Android APK files.

## Features

- APK Unpacking and Decompilation
- Manifest Analysis
- Database Encryption Analysis
- Suspicious API Detection
- YARA Signature-based Analysis
- Comprehensive Reporting (HTML, PDF, JSON)

## Prerequisites

### Windows
1. Install Python 3.8 or higher from [python.org](https://www.python.org/downloads/)
2. Install Git from [git-scm.com](https://git-scm.com/download/win)
3. Install Java Development Kit (JDK) 8 or higher from [Oracle](https://www.oracle.com/java/technologies/downloads/) or [AdoptOpenJDK](https://adoptium.net/)

### Mac
1. Install Python 3.8 or higher:
   ```bash
   brew install python
   ```
2. Install Git:
   ```bash
   brew install git
   ```
3. Install Java Development Kit (JDK) 8 or higher:
   ```bash
   brew install openjdk
   ```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/darlene-x.git
   cd darlene-x
   ```

2. Create and activate a virtual environment:

   **Windows:**
   ```bash
   python -m venv venv
   .\venv\Scripts\activate
   ```

   **Mac:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirement.txt
   ```

## Usage

1. Ensure your virtual environment is activated
2. Run the tool:
   ```bash
   python -m darlene_x.darlene_x_cli /path/to/your.apk
   ```

## Output

The tool provides detailed analysis in multiple formats:
- Console output with progress indicators
- HTML, PDF, and JSON reports
- Extracted APK contents and decompiled code

## Troubleshooting

### Windows
- If you encounter "python not found" error, ensure Python is added to your PATH during installation
- If you get permission errors, run PowerShell as Administrator
- For Java-related issues, verify JAVA_HOME environment variable is set correctly

### Mac
- If you get "permission denied" errors, use `sudo` before the command
- For Python version conflicts, ensure you're using the correct Python version with `python3` command
- If Java is not found, link it using:
  ```bash
  sudo ln -sfn /usr/local/opt/openjdk/libexec/openjdk.jdk /Library/Java/JavaVirtualMachines/openjdk.jdk
  ```

## Support

For issues and feature requests, please create an issue on the GitHub repository.
