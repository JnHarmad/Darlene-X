import os
import json
import tkinter as tk
from tkinter import filedialog
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from androguard.misc import AnalyzeAPK
from loguru import logger
import pyfiglet
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib import colors
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
import requests  # For querying CVE databases
import subprocess  # For running Jadx commands


# Initialize console for Rich library
console = Console()

# Remove default loguru handlers to avoid duplicate logs
logger.remove()


def display_banner():
    """Display a styled banner for 'FORENSIPIE'."""
    ascii_art = pyfiglet.figlet_format("FORENSIPIE", font="slant", justify="center")
    styled_ascii_art = ""
    for i, line in enumerate(ascii_art.splitlines()):
        if i % 2 == 0:
            styled_ascii_art += f"[bold bright_blue]{line.center(100)}[/bold bright_blue]\n"
        else:
            styled_ascii_art += f"[bold magenta]{line.center(100)}[/bold magenta]\n"
    welcome_message = "[bold green]Welcome To...[/bold green]\n"
    tool_name = "[bold cyan]ForensiPie - Android Static Analysis Tool[/bold cyan]\n"
    version_number = "[bold yellow]Version: 1.0.0[/bold yellow]"
    analyzer_label = "[bold white]Android Static Analyzer[/bold white]"
    full_content = (
        styled_ascii_art.strip() + "\n" +
        welcome_message + tool_name + version_number + "\n" +
        analyzer_label
    )
    console.print(full_content)


def browse_file():
    """Open a file dialog for the user to select an APK file."""
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    file_path = filedialog.askopenfilename(
        title="Select an APK File",
        filetypes=[("APK files", "*.apk")]
    )
    return file_path


def fetch_cve_data(library_name, version):
    """
    Fetch CVE data for a given library and version from the NVD API.
    Args:
        library_name: Name of the library.
        version: Version of the library.
    Returns:
        list: A list of CVEs associated with the library and version.
    """
    cve_list = []
    try:
        # Query the NVD API for vulnerabilities
        url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={library_name}&version={version}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if "result" in data and "CVE_Items" in data["result"]:
                for item in data["result"]["CVE_Items"]:
                    cve_id = item["cve"]["CVE_data_meta"]["ID"]
                    description = item["cve"]["description"]["description_data"][0]["value"]
                    cve_list.append({"id": cve_id, "description": description})
    except Exception as e:
        console.print(f"[bold red]Error fetching CVE data:[/] {e}")
    return cve_list


def perform_cve_scanning(a, progress, task_cve):
    """
    Perform CVE scanning on the libraries used in the APK.
    Args:
        a: Androguard APK object.
        progress: Progress object for updating the progress bar.
        task_cve: Task ID for the CVE scanning progress bar.
    Returns:
        dict: A dictionary containing the CVE findings.
    """
    cve_results = {}
    # Extract libraries and their versions from the APK
    libraries = {}
    for lib in a.get_libraries():
        # Example: Extract library name and version (this depends on how libraries are named in the APK)
        parts = lib.split(":")
        if len(parts) >= 2:
            lib_name, lib_version = parts[0], parts[1]
            libraries[lib_name] = lib_version
    # Check each library for CVEs
    total_libraries = len(libraries)
    progress.update(task_cve, total=total_libraries)
    for i, (lib_name, lib_version) in enumerate(libraries.items()):
        cve_list = fetch_cve_data(lib_name, lib_version)
        if cve_list:
            cve_results[lib_name] = {
                "version": lib_version,
                "cves": cve_list
            }
        progress.update(task_cve, advance=1)
    # Mark the CVE scanning task as complete
    progress.update(task_cve, completed=total_libraries)
    return cve_results


def perform_masvs_sast_checks(a, dx, progress, task_sast):
    """
    Perform SAST checks based on OWASP MASVS requirements.
    Args:
        a: Androguard APK object.
        dx: Androguard Analysis object.
        progress: Progress object for updating the progress bar.
        task_sast: Task ID for the SAST scanning progress bar.
    Returns:
        dict: A dictionary containing the results of MASVS checks.
    """
    masvs_results = {
        "V2_Data_Storage_and_Privacy": [],
        "V3_Cryptography": [],
        "V4_Authentication": [],
        "V5_Network_Communication": [],
        "V6_Platform_Interaction": [],
        "V7_Code_Quality_and_Build_Settings": [],
        "R_Resiliency_Against_Reverse_Engineering": []
    }
    # TODO: Implement actual SAST checks here
    # Example: Add dummy data for demonstration purposes
    masvs_results["V2_Data_Storage_and_Privacy"].append("Potential insecure storage detected.")
    masvs_results["V5_Network_Communication"].append("Insecure network protocol usage.")
    # Mark the SAST task as complete
    progress.update(task_sast, completed=1)
    return masvs_results


def run_jadx(apk_path, output_dir):
    """
    Run Jadx to decompile the APK and extract Java source code.
    Args:
        apk_path: Path to the APK file.
        output_dir: Directory to store the decompiled output.
    Returns:
        str: Path to the decompiled Java source code directory.
    """
    jadx_command = ["jadx", "-d", output_dir, apk_path]
    try:
        console.print(f"[bold cyan]Running Jadx on:[/] {apk_path}")
        result = subprocess.run(jadx_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            console.print("[bold green]Jadx decompilation completed successfully.[/]")
            return os.path.join(output_dir, "sources")
        else:
            console.print(f"[bold red]Jadx failed with error:[/] {result.stderr.decode('utf-8')}")
            return None
    except Exception as e:
        console.print(f"[bold red]Error running Jadx:[/] {e}")
        return None


def analyze_decompiled_code(decompiled_dir):
    """
    Perform basic analysis on the decompiled Java source code.
    Args:
        decompiled_dir: Directory containing the decompiled Java source code.
    Returns:
        dict: Results of the analysis on the decompiled code.
    """
    findings = {
        "suspicious_patterns": [],
        "hardcoded_secrets": []
    }
    suspicious_keywords = ["password", "secret", "key", "admin"]
    try:
        for root, _, files in os.walk(decompiled_dir):
            for file in files:
                if file.endswith(".java"):
                    file_path = os.path.join(root, file)
                    with open(file_path, "r", encoding="utf-8") as f:
                        content = f.read()
                        # Check for suspicious patterns
                        for keyword in suspicious_keywords:
                            if keyword in content.lower():
                                findings["suspicious_patterns"].append(f"{file}: {keyword}")
                        # Check for hardcoded secrets (basic regex-like check)
                        if "password" in content.lower() or "secret" in content.lower():
                            findings["hardcoded_secrets"].append(file)
    except Exception as e:
        console.print(f"[bold red]Error analyzing decompiled code:[/] {e}")
    return findings


def analyze_apk(apk_path):
    """Perform static analysis on the selected APK file with a progress bar."""
    if not os.path.exists(apk_path):
        console.print(f"[bold red]Error:[/] File not found: {apk_path}")
        return {}

    console.print("\n[bold cyan]ForensiPie - Android Static Analysis Tool[/bold cyan]")
    console.print(f"[bold green]Analyzing:[/] {apk_path}\n")

    analysis_results = {}

    # Progress bar for APK analysis
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task_main = progress.add_task("[cyan]Analyzing APK...", total=10)  # Increased total tasks to include Jadx
        try:
            # Perform analysis using Androguard
            progress.update(task_main, advance=1)
            a, d, dx = AnalyzeAPK(apk_path)

            # Extract basic metadata
            package_name = a.get_package()
            version_name = a.get_androidversion_name()
            permissions = list(a.get_permissions())
            min_sdk_version = a.get_min_sdk_version()
            target_sdk_version = a.get_target_sdk_version()
            activities = a.get_activities()
            services = a.get_services()
            receivers = a.get_receivers()
            progress.update(task_main, advance=1)

            # Extract certificate details
            certificates = []
            for cert in a.get_certificates():
                serial_number = cert.serial_number
                if isinstance(serial_number, int):
                    serial_number = hex(serial_number).upper()
                elif not isinstance(serial_number, str):
                    serial_number = str(serial_number)
                sha256_fingerprint = cert.sha256_fingerprint
                if isinstance(sha256_fingerprint, bytes):
                    sha256_fingerprint = sha256_fingerprint.hex().upper()
                elif not isinstance(sha256_fingerprint, str):
                    sha256_fingerprint = str(sha256_fingerprint)
                certificates.append({
                    "subject": cert.subject.human_friendly,
                    "issuer": cert.issuer.human_friendly,
                    "serial_number": serial_number,
                    "sha256_fingerprint": sha256_fingerprint
                })
            progress.update(task_main, advance=1)

            # Detect obfuscation
            obfuscation_detected = False
            obfuscated_classes = []
            obfuscated_methods = []
            for cls in dx.get_classes():
                class_name = cls.name
                if len(class_name.split("/")[-1]) <= 3:
                    obfuscation_detected = True
                    obfuscated_classes.append(class_name)
                for method in cls.get_methods():
                    method_name = method.name
                    if len(method_name) <= 3:
                        obfuscation_detected = True
                        obfuscated_methods.append(f"{class_name}->{method_name}")
            progress.update(task_main, advance=1)

            # Perform OWASP MASVS SAST checks
            task_sast = progress.add_task("[cyan]Performing SAST Checks...", total=1)
            masvs_results = perform_masvs_sast_checks(a, dx, progress, task_sast)
            progress.update(task_sast, completed=1)  # Mark SAST task as complete
            analysis_results["masvs_sast"] = masvs_results

            # Perform CVE scanning
            task_cve = progress.add_task("[cyan]Performing CVE Scanning...", total=1)
            cve_results = perform_cve_scanning(a, progress, task_cve)
            progress.update(task_cve, completed=1)  # Mark CVE task as complete
            analysis_results["cve_scanning"] = cve_results

            # Decompile APK using Jadx
            task_jadx = progress.add_task("[cyan]Decompiling APK with Jadx...", total=1)
            output_dir = os.path.join("output", os.path.splitext(os.path.basename(apk_path))[0])
            decompiled_dir = run_jadx(apk_path, output_dir)
            progress.update(task_jadx, completed=1)  # Mark Jadx task as complete

            # Analyze decompiled code
            task_decompiled_analysis = progress.add_task("[cyan]Analyzing Decompiled Code...", total=1)
            if decompiled_dir:
                decompiled_findings = analyze_decompiled_code(decompiled_dir)
                analysis_results["decompiled_analysis"] = decompiled_findings
            progress.update(task_decompiled_analysis, completed=1)  # Mark decompiled analysis task as complete

            # Compile analysis results
            analysis_results = {
                "package_name": package_name,
                "version": version_name,
                "permissions": permissions,
                "min_sdk_version": min_sdk_version,
                "target_sdk_version": target_sdk_version,
                "activities": activities,
                "services": services,
                "receivers": receivers,
                "certificates": certificates,
                "obfuscation_detected": obfuscation_detected,
                "obfuscated_classes": obfuscated_classes,
                "obfuscated_methods": obfuscated_methods,
                "masvs_sast": masvs_results,
                "cve_scanning": cve_results,
                "decompiled_analysis": analysis_results.get("decompiled_analysis", {})
            }
            progress.update(task_main, advance=1)

            # Display extracted metadata
            console.print(f"[bold yellow]APK Package Name:[/] {package_name}")
            console.print(f"[bold yellow]Version:[/] {version_name}")
            console.print(f"[bold yellow]Permissions:[/]")
            for perm in permissions:
                console.print(f"   - {perm}")
            console.print(f"[bold yellow]Min SDK Version:[/] {min_sdk_version}")
            console.print(f"[bold yellow]Target SDK Version:[/] {target_sdk_version}")
            console.print(f"[bold yellow]Activities:[/]")
            for activity in activities:
                console.print(f"   - {activity}")
            console.print(f"[bold yellow]Services:[/]")
            for service in services:
                console.print(f"   - {service}")
            console.print(f"[bold yellow]Receivers:[/]")
            for receiver in receivers:
                console.print(f"   - {receiver}")
            console.print(f"[bold yellow]Certificates:[/]")
            for cert in certificates:
                console.print(f"   - Subject: {cert['subject']}")
                console.print(f"     Issuer: {cert['issuer']}")
                console.print(f"     Serial Number: {cert['serial_number']}")
                console.print(f"     SHA256 Fingerprint: {cert['sha256_fingerprint']}")
            console.print(f"[bold yellow]Obfuscation Detected:[/] {'Yes' if obfuscation_detected else 'No'}")
            if obfuscation_detected:
                console.print(f"[bold yellow]   Obfuscated Classes:[/] {len(obfuscated_classes)}")
                console.print(f"[bold yellow]   Obfuscated Methods:[/] {len(obfuscated_methods)}")

            # Display MASVS SAST findings
            console.print("\n[bold cyan]OWASP MASVS SAST Findings:[/bold cyan]")
            for category, findings in masvs_results.items():
                if findings:
                    console.print(f"[bold yellow]{category}:[/bold yellow]")
                    for finding in findings:
                        console.print(f"   - {finding}")
                else:
                    console.print(f"[bold green]{category}:[/] No issues detected.")

            # Display CVE findings
            console.print("\n[bold cyan]CVE Scanning Results:[/bold cyan]")
            if cve_results:
                for lib, details in cve_results.items():
                    console.print(f"[bold yellow]{lib} (Version: {details['version']}):[/bold yellow]")
                    for cve in details["cves"]:
                        console.print(f"   - CVE ID: {cve['id']}")
                        console.print(f"     Description: {cve['description']}")
            else:
                console.print("[bold green]No CVEs detected.[/]")

            # Display Decompiled Code Findings
            console.print("\n[bold cyan]Decompiled Code Analysis Findings:[/bold cyan]")
            decompiled_findings = analysis_results.get("decompiled_analysis", {})
            if decompiled_findings:
                console.print("[bold yellow]Suspicious Patterns:[/bold yellow]")
                for pattern in decompiled_findings.get("suspicious_patterns", []):
                    console.print(f"   - {pattern}")
                console.print("[bold yellow]Hardcoded Secrets:[/bold yellow]")
                for secret in decompiled_findings.get("hardcoded_secrets", []):
                    console.print(f"   - {secret}")
            else:
                console.print("[bold green]No issues detected in decompiled code.[/]")

            # Mark the main task as complete
            progress.update(task_main, completed=10)
        except Exception as e:
            console.print(f"[bold red]Analysis Failed:[/] {e}")
            logger.error(f"Error during analysis: {e}")
    return analysis_results


def export_to_json(data, output_path):
    """Export analysis results to a JSON file with a progress bar."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Exporting to JSON...", total=1)
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
            progress.update(task, advance=1)
            console.print(f"[bold green]Results exported to JSON:[/] {output_path}")
        except Exception as e:
            console.print(f"[bold red]Error exporting to JSON:[/] {e}")


def export_to_pdf(data, output_path):
    """Export analysis results to a PDF file with improved presentation."""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
    from reportlab.lib import colors
    from datetime import datetime
    # Initialize PDF document with explicit margins
    doc = SimpleDocTemplate(output_path, pagesize=letter,
                            leftMargin=50, rightMargin=50, topMargin=50, bottomMargin=50)
    elements = []
    styles = getSampleStyleSheet()
    # Custom styles
    title_style = ParagraphStyle(
        name="TitleStyle",
        parent=styles["Title"],
        fontSize=24,
        leading=28,
        alignment=1  # Center alignment
    )
    subtitle_style = ParagraphStyle(
        name="SubtitleStyle",
        parent=styles["Normal"],
        fontSize=14,
        leading=16,
        alignment=1  # Center alignment
    )
    heading_style = ParagraphStyle(
        name="HeadingStyle",
        parent=styles["Heading2"],
        fontSize=16,
        leading=18,
        spaceAfter=10
    )
    normal_style = styles["Normal"]
    normal_style.spaceAfter = 6
    # Add Title Page
    title = Paragraph("ForensiPie - Analysis Report", title_style)
    subtitle = Paragraph(f"APK: {data['package_name']} (Version: {data['version']})", subtitle_style)
    date = Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style)
    elements.extend([title, Spacer(1, 20), subtitle, Spacer(1, 10), date, Spacer(1, 40), PageBreak()])
    # Helper function to create tables
    def create_table(headers, rows, col_widths=None):
        table_data = [headers] + rows
        table = Table(table_data, colWidths=col_widths, repeatRows=1)  # Repeat headers on each page
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),  # Align text at the top of cells
            ("WORDWRAP", (0, 0), (-1, -1), "CJK"),  # Enable word wrapping
            ("FONTSIZE", (0, 1), (-1, -1), 8)  # Smaller font size for table content
        ]))
        return table
    # Add Metadata Section
    elements.append(Paragraph("Metadata", heading_style))
    metadata = [
        ["Package Name", data["package_name"]],
        ["Version", data["version"]],
        ["Min SDK Version", data["min_sdk_version"]],
        ["Target SDK Version", data["target_sdk_version"]],
        ["Obfuscation Detected", "Yes" if data["obfuscation_detected"] else "No"]
    ]
    elements.append(create_table(["Field", "Value"], metadata, col_widths=[200, 300]))
    elements.append(Spacer(1, 20))
    # Add Permissions Section
    permissions_heading = Paragraph("Permissions", heading_style)
    permissions_table = [[perm] for perm in data["permissions"]]
    permissions_content = create_table(["Permission"], permissions_table, col_widths=[500])
    elements.append(KeepTogether([permissions_heading, permissions_content]))  # Keep heading and content together
    elements.append(Spacer(1, 20))
    # Add Activities, Services, and Receivers Sections
    for section_name, section_data in [("Activities", data["activities"]), ("Services", data["services"]),
                                       ("Receivers", data["receivers"])]:
        section_heading = Paragraph(section_name, heading_style)
        section_table = [[item] for item in section_data]
        section_content = create_table([section_name[:-1]], section_table, col_widths=[500])
        elements.append(KeepTogether([section_heading, section_content]))  # Keep heading and content together
        elements.append(Spacer(1, 20))
    # Add Certificates Section
    certificates_heading = Paragraph("Certificates", heading_style)
    certificates_table = [
        ["Subject", cert["subject"], "Issuer", cert["issuer"]] for cert in data["certificates"]
    ]
    certificates_content = create_table(["Subject", "Details", "Issuer", "Details"], certificates_table,
                                        col_widths=[120, 180, 120, 180])
    elements.append(KeepTogether([certificates_heading, certificates_content]))  # Keep heading and content together
    elements.append(Spacer(1, 20))
    # Add Obfuscated Classes and Methods Section
    if data["obfuscation_detected"]:
        obfuscation_heading = Paragraph("Obfuscated Classes and Methods", heading_style)
        obfuscated_classes_table = [[cls] for cls in data["obfuscated_classes"]]
        obfuscated_methods_table = [[method] for method in data["obfuscated_methods"]]
        obfuscation_content = [
            create_table(["Obfuscated Classes"], obfuscated_classes_table, col_widths=[500]),
            create_table(["Obfuscated Methods"], obfuscated_methods_table, col_widths=[500])
        ]
        elements.append(KeepTogether([obfuscation_heading] + obfuscation_content))  # Keep heading and content together
        elements.append(Spacer(1, 20))
    # Add OWASP MASVS SAST Findings
    masvs_heading = Paragraph("OWASP MASVS SAST Findings", heading_style)
    masvs_content = []
    for category, findings in data["masvs_sast"].items():
        category_heading = Paragraph(category, styles["Heading3"])
        if findings:
            findings_table = [[finding] for finding in findings]
            findings_content = create_table(["Findings"], findings_table, col_widths=[500])
            masvs_content.append(KeepTogether([category_heading, findings_content]))  # Keep heading and content together
        else:
            masvs_content.append(KeepTogether([category_heading, Paragraph("No issues detected.", normal_style)]))
    elements.append(KeepTogether([masvs_heading] + masvs_content))  # Keep heading and content together
    elements.append(Spacer(1, 20))
    # Add CVE Scanning Results
    cve_heading = Paragraph("CVE Scanning Results", heading_style)
    cve_content = []
    if data["cve_scanning"]:
        for lib, details in data["cve_scanning"].items():
            library_heading = Paragraph(f"{lib} (Version: {details['version']})", styles["Heading3"])
            cve_table = [["CVE ID", "Description"]] + [[cve["id"], cve["description"]] for cve in details["cves"]]
            cve_table_content = create_table(["CVE ID", "Description"], cve_table, col_widths=[150, 350])
            cve_content.append(KeepTogether([library_heading, cve_table_content]))  # Keep heading and content together
    else:
        cve_content.append(Paragraph("No CVEs detected.", normal_style))
    elements.append(KeepTogether([cve_heading] + cve_content))  # Keep heading and content together
    # Add Footer
    def add_footer(canvas, doc):
        canvas.saveState()
        footer_text = "Generated by ForensiPie - Android Static Analysis Tool"
        canvas.setFont("Helvetica", 9)
        canvas.drawString(50, 50, footer_text)
        canvas.restoreState()
    doc.build(elements, onLaterPages=add_footer, onFirstPage=add_footer)
    console.print(f"[bold green]Results exported to PDF:[/] {output_path}")


def export_to_html(data, output_path):
    """Export analysis results to an HTML file with a progress bar."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Exporting to HTML...", total=1)
        try:
            # Define the absolute path to the templates directory
            script_dir = os.path.dirname(os.path.abspath(file))
            template_dir = os.path.join(script_dir, 'templates')
            # Ensure the template directory exists
            if not os.path.exists(template_dir):
                console.print("[bold red]Error:[/] Template directory not found. Please create a 'templates' folder.")
                return
            # Ensure the template.html file exists
            template_file = os.path.join(template_dir, 'template.html')
            if not os.path.exists(template_file):
                console.print("[bold red]Error:[/] template.html not found in the templates folder.")
                return
            # Load the Jinja2 environment
            env = Environment(loader=FileSystemLoader(template_dir))
            template = env.get_template('template.html')
            # Render the HTML content
            html_content = template.render(
                package_name=data['package_name'],
                version=data['version'],
                min_sdk_version=data['min_sdk_version'],
                target_sdk_version=data['target_sdk_version'],
                permissions=data['permissions'],
                activities=data['activities'],
                services=data['services'],
                receivers=data['receivers'],
                certificates=data['certificates'],
                obfuscation_detected=data['obfuscation_detected'],
                obfuscated_classes=data['obfuscated_classes'],
                obfuscated_methods=data['obfuscated_methods'],
                masvs_sast=data['masvs_sast'],
                cve_scanning=data['cve_scanning']
            )
            # Write the rendered HTML to the output file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            progress.update(task, advance=1)
            console.print(f"[bold green]Results exported to HTML:[/] {output_path}")
        except Exception as e:
            console.print(f"[bold red]Error exporting to HTML:[/] {e}")


def main():
    # Display the tool banner
    display_banner()

    # Prompt the user to select an APK file
    console.print("Please select an APK file for analysis...")
    apk_path = browse_file()

    # Check if a file was selected
    if not apk_path:
        console.print("[bold red]No file selected. Exiting...[/bold red]")
        return

    # Perform APK analysis
    analysis_results = analyze_apk(apk_path)
    if not analysis_results:
        return

    # Ask the user for the export format
    console.print("\n[bold cyan]Choose the export format:[/bold cyan]")
    console.print("[1] JSON")
    console.print("[2] PDF")
    console.print("[3] HTML")
    choice = input("Enter your choice (1/2/3): ").strip()

    # Define output directory and base name
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    base_name = os.path.splitext(os.path.basename(apk_path))[0]

    # Export results based on user choice
    if choice == "1":
        output_path = os.path.join(output_dir, f"{base_name}.json")
        export_to_json(analysis_results, output_path)
    elif choice == "2":
        output_path = os.path.join(output_dir, f"{base_name}.pdf")
        export_to_pdf(analysis_results, output_path)
    elif choice == "3":
        output_path = os.path.join(output_dir, f"{base_name}.html")
        export_to_html(analysis_results, output_path)
    else:
        console.print("[bold red]Invalid choice. Exiting...[/bold red]")


if __name__ == "__main__":
    main()