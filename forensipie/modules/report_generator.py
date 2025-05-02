import os
import json
from datetime import datetime
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from rich.console import Console
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
from jinja2 import Environment, FileSystemLoader

console = Console()

# FIXED HTML Template Setup
# Get the path to the module directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Look for templates in the same directory as the script
template_dir = os.path.join(SCRIPT_DIR, 'templates')
# Create templates directory if it doesn't exist
os.makedirs(template_dir, exist_ok=True)
# Create jinja environment
env = Environment(loader=FileSystemLoader(template_dir))

# Save the template file to the templates directory
def ensure_template_exists():
    template_path = os.path.join(template_dir, 'template.html')
    # Only create the template if it doesn't exist
    if not os.path.exists(template_path):
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ForensiPie - Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2, h3 { color: #444; }
        ul { margin-top: 0; }
        .verdict { font-weight: bold; font-size: 1.2em; }
        .malicious { color: red; }
        .safe { color: green; }
    </style>
</head>
<body>
    <h1>ForensiPie - Static Analysis Report</h1>

    <h2>Maliciousness Verdict</h2>
    {% if maliciousness.status == "MALICIOUS" %}
        <p class="verdict malicious">⚠️ Device Classified as MALICIOUS</p>
        <ul>
            {% for reason in maliciousness.reasons %}
                <li>{{ reason }}</li>
            {% endfor %}
        </ul>
    {% elif maliciousness.status == "SAFE" %}
        <p class="verdict safe">✅ Device Classified as SAFE — No major issues detected.</p>
    {% else %}
        <p>Status: {{ maliciousness.status }}</p>
        <p>Error: {{ maliciousness.error }}</p>
    {% endif %}

    <h2>Module-wise Analysis</h2>
    {% for module, result in analysis.items() %}
        <h3>{{ module.replace("_", " ") | title }}</h3>
        {% if result is string %}
            <p>{{ result }}</p>
        {% elif result is mapping %}
            <ul>
                {% for key, val in result.items() %}
                    <li><strong>{{ key }}:</strong> {{ val }}</li>
                {% endfor %}
            </ul>
        {% elif result is iterable %}
            <ul>
                {% for item in result %}
                    <li>{{ item }}</li>
                {% endfor %}
            </ul>
        {% endif %}
    {% endfor %}
</body>
</html>""")
        console.print(f"[green]Template file created at:[/green] {template_path}")

def generate_pdf_report(data, output_path):
    doc = SimpleDocTemplate(output_path, pagesize=letter, leftMargin=50, rightMargin=50, topMargin=50, bottomMargin=50)
    elements = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(name="TitleStyle", parent=styles["Title"], fontSize=24, leading=28, alignment=1)
    subtitle_style = ParagraphStyle(name="SubtitleStyle", parent=styles["Normal"], fontSize=14, leading=16, alignment=1)
    heading_style = ParagraphStyle(name="HeadingStyle", parent=styles["Heading2"], fontSize=16, leading=18, spaceAfter=10)
    subheading_style = ParagraphStyle(name="SubHeadingStyle", parent=styles["Heading3"], fontSize=14, leading=16, spaceAfter=8)
    normal_style =  ParagraphStyle(name="NormalCopy", parent=styles["Normal"])
    normal_style.spaceAfter = 6

    elements.append(Paragraph("ForensiPie - Analysis Report", title_style))
    date = Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style)
    elements.extend([Spacer(1, 20), date, Spacer(1, 40)])

    decision = data.get("maliciousness_decision", {})
    elements.append(Paragraph("Maliciousness Verdict", heading_style))
    if decision.get("status") == "MALICIOUS":
        elements.append(Paragraph("⚠️ Device Classified as MALICIOUS", normal_style))
        elements.append(Paragraph("Reasons:", normal_style))
        for reason in decision.get("reasons", []):
            elements.append(Paragraph(f"• {reason}", normal_style))
    elif decision.get("status") == "SAFE":
        elements.append(Paragraph("✅ Device Classified as SAFE — No major issues detected.", normal_style))
    else:
        elements.append(Paragraph(f"Status: {decision.get('status', 'Unknown')}", normal_style))
        if decision.get('error'):
            elements.append(Paragraph(f"Error: {decision.get('error', 'N/A')}", normal_style))

    analysis = data.get("analysis_result", {})
    elements.append(PageBreak())

    # APK Info
    apk_info = analysis.get("apk_info", {})
    elements.append(Paragraph("APK Information", heading_style))
    for key in ["package_name", "version", "file_size", "sha256"]:
        if apk_info.get(key):
            elements.append(Paragraph(f"{key.replace('_', ' ').title()}: {apk_info[key]}", normal_style))
    dex_stats = apk_info.get("dex_statistics", {})
    elements.append(Paragraph(f"Classes: {dex_stats.get('class_count', 0)}", normal_style))
    elements.append(Paragraph(f"Methods: {dex_stats.get('method_count', 0)}", normal_style))

    elements.append(Spacer(1, 20))

    # Manifest
    manifest = analysis.get("manifest", {})
    elements.append(Paragraph("Manifest Details", heading_style))
    sdk = manifest.get("sdk_versions", {})
    elements.append(Paragraph(f"Min SDK: {sdk.get('min_sdk', 'N/A')}, Target SDK: {sdk.get('target_sdk', 'N/A')}", normal_style))
    for section in ["permissions", "broadcast_receivers", "content_providers", "activities"]:
        if manifest.get(section):
            elements.append(Paragraph(section.replace('_', ' ').title() + ":", subheading_style))
            for item in manifest[section]:
                elements.append(Paragraph(f"• {item}", normal_style))
    if manifest.get("certificates"):
        elements.append(Paragraph("Certificates:", subheading_style))
        for cert in manifest["certificates"]:
            elements.append(Paragraph(f"MD5: {cert['md5']} | SHA1: {cert['sha1']} | SHA256: {cert['sha256']}", normal_style))

    elements.append(PageBreak())

    # Database Encryption
    db_enc = analysis.get("database_encryption", {})
    elements.append(Paragraph("Database Encryption Status", heading_style))
    for db in db_enc.get("databases", []):
        elements.append(Paragraph(f"{db['path']} - {db['encryption_status']}", normal_style))

    elements.append(Spacer(1, 20))

    # Suspicious APIs
    suspicious = analysis.get("suspicious_apis", {})
    elements.append(Paragraph("Suspicious API Calls", heading_style))
    for api in suspicious.get("apis", []):
        elements.append(Paragraph(f"• {api['method']} - {api['api_call']} - {api['description']}", normal_style))

    elements.append(PageBreak())

    # Signature Analysis
    sig = analysis.get("signature_analysis", {})
    elements.append(Paragraph("Signature Analysis", heading_style))
    for category, matches in sig.items():
        if category in ["status", "error"]:
            continue
        elements.append(Paragraph(category.replace("_", " ").title(), subheading_style))
        for match in matches:
            elements.append(Paragraph(f"• {match['file']} - Matches: {', '.join(match['matches'])}", normal_style))

    doc.build(elements)
    console.log(f"[green]PDF report saved to:[/green] {output_path}")

def generate_json_report(data, output_path):
    json_data = {
        "metadata": {
            "generated_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "report_version": "1.0"
        },
        "apk_info": data.get("analysis_result", {}).get("apk_info", {}),
        "manifest": data.get("analysis_result", {}).get("manifest", {}),
        "database_encryption": data.get("analysis_result", {}).get("database_encryption", {}),
        "suspicious_apis": data.get("analysis_result", {}).get("suspicious_apis", {}),
        "signature_analysis": data.get("analysis_result", {}).get("signature_analysis", {}),
        "maliciousness_decision": data.get("maliciousness_decision", {})
    }
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=4)
    console.print(f"[bold green]Results exported to JSON:[/] {output_path}")


def generate_html_report(data, output_path):
    ensure_template_exists()
    template = env.get_template("template.html")

    analysis_result = data.get("analysis_result", {})
    analysis={
        "apk_info": analysis_result.get("apk_info", {}),
        "manifest": analysis_result.get("manifest", {}),
        "database_encryption": analysis_result.get("database_encryption", {}),
        "suspicious_apis": analysis_result.get("suspicious_apis", {}),
        "signature_analysis": analysis_result.get("signature_analysis", {})
    }
    maliciousness = data.get("maliciousness_decision", {})

    html_content = template.render(
        analysis=analysis,
        maliciousness=maliciousness
    )
    with open(output_path, 'w', encoding='utf-8') as html_file:
        html_file.write(html_content)
    console.print(f"[bold green]Results exported to HTML:[/] {output_path}")


def export_report(data, report_dir) -> dict:
    os.makedirs(report_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_status = {"pdf": False, "json": False, "html": False}

    pdf_path = os.path.join(report_dir, f"report_{timestamp}.pdf")
    json_path = os.path.join(report_dir, f"report_{timestamp}.json")
    html_path = os.path.join(report_dir, f"report_{timestamp}.html")

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]Generating Reports..."),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        transient=True,
        console=console
    ) as progress:
        task = progress.add_task("report", total=3)

        try:
            generate_pdf_report(data, pdf_path)
            report_status["pdf"] = True
        except Exception as e:
            console.print(f"[red]PDF generation failed: {e}[/red]")
        progress.advance(task)

        try:
            generate_json_report(data, json_path)
            report_status["json"] = True
        except Exception as e:
            console.print(f"[red]JSON generation failed: {e}[/red]")
        progress.advance(task)

        try:
            generate_html_report(data, html_path)
            report_status["html"] = True
        except Exception as e:
            console.print(f"[red]HTML generation failed: {e}[/red]")
        progress.advance(task)

    return report_status

def generate_reports(data, report_dir) -> dict:
    return export_report(data, report_dir)