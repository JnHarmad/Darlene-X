import os
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from jinja2 import Environment, FileSystemLoader


def generate_reports(data, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    
    # All fallback mechanisms removed - we will report the data we actually have
    # No hardcoded values or parsing from console output

    status = {
        "pdf": generate_pdf(data, os.path.join(output_dir, "report.pdf")),
        "json": generate_json(data, os.path.join(output_dir, "report.json")),
        "html": generate_html(data, os.path.join(output_dir, "report.html"))
    }
    return status


def generate_json(data, output_path):
    try:
        # Get suspicious API calls data with fallback mechanism
        api_info = data['analysis_result'].get('suspicious_apis', {})
        apis = api_info.get("APIs", [])
        if not apis and 'suspicious_api_calls' in data['analysis_result']:
            api_calls_data = data['analysis_result'].get('suspicious_api_calls', {})
            apis = api_calls_data.get("suspicious_apis", [])

        # Get signature analysis data with fallback mechanism
        sig_info = data['analysis_result'].get('signature_analysis', {})
        matches = sig_info.get("Matches", [])
        if not matches and 'signature' in data['analysis_result']:
            sig_data = data['analysis_result'].get('signature', {})
            yara_results = sig_data.get("yara_results", {})
            for category, result in yara_results.items():
                category_matches = result.get("matches", [])
                if category_matches:
                    for match in category_matches:
                        if isinstance(match, dict):
                            matches.append({
                                "file": match.get("file", "Unknown File"),
                                "rule": match.get("rule", category)
                            })

        formatted_data = {
            "ForensiPie Report": {
                "Timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "Tool Version": "1.0.0",
                "Classification": {
                    "Status": data['maliciousness_decision'].get("status", "UNKNOWN"),
                    "Reasons": data['maliciousness_decision'].get("reasons", [])
                },
                "APK Overview": data['analysis_result'].get('apk_overview', {}),
                "Module Wise Analysis": {
                    "Manifest Analysis": {
                        "Minimum SDK": data['analysis_result'].get('manifest', {}).get("Minimum SDK"),
                        "Target SDK": data['analysis_result'].get('manifest', {}).get("Target SDK"),
                        "Permissions": data['analysis_result'].get('manifest', {}).get("Permissions", []),
                        "Broadcast Receivers": data['analysis_result'].get('manifest', {}).get("Broadcast Receivers", []),
                        "Content Providers": data['analysis_result'].get('manifest', {}).get("Content Providers", []),
                        "Activities": data['analysis_result'].get('manifest', {}).get("Activities", []),
                        "Certificates": data['analysis_result'].get('manifest', {}).get("Certificates", [])
                    },
                    "Database Encryption State": {
                        "Encryption Status": data['analysis_result'].get('encryption', {}).get("Encryption Status", "Not Available")
                    },
                    "Suspicious API Calls": apis,
                    "Signature Based Analysis": matches
                }
            }
        }

        with open(output_path, 'w') as f:
            json.dump(formatted_data, f, indent=4)
        return True

    except Exception as e:
        print(f"[!] JSON Report Error: {e}")
        return False



def generate_pdf(data, output_path):
    try:
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        styles = getSampleStyleSheet()
        normal_style = styles["Normal"]
        title_style = styles["Title"]
        heading2 = styles["Heading2"]
        heading3 = styles["Heading3"]
        custom_style = ParagraphStyle(name='Custom', fontSize=10, leading=14)

        flowables = []

        # Title and Metadata
        flowables.append(Paragraph("<b>FORENSIPIE ANALYSIS REPORT</b>", title_style))
        flowables.append(Spacer(1, 12))
        flowables.append(Paragraph(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", custom_style))
        flowables.append(Paragraph("Tool Version: 1.0.0", custom_style))
        flowables.append(Spacer(1, 12))

        # Verdict
        decision = data['maliciousness_decision']
        flowables.append(Paragraph(f"<b>DEVICE IS CLASSIFIED AS {decision['status']}</b>", heading2))
        if decision["status"] == "MALICIOUS":
            flowables.append(Paragraph("Reasons:", heading3))
            for reason in decision.get('reasons', []):
                flowables.append(Paragraph(f"- {reason}", custom_style))
        flowables.append(Spacer(1, 12))

        # APK Overview
        overview = data['analysis_result'].get('apk_overview', {})
        flowables.append(Paragraph("<b>APK OVERVIEW</b>", heading2))
        if not overview:
            # If apk_overview is empty, try to populate from manifest data
            manifest_data = data['analysis_result'].get('manifest', {})
            if manifest_data:
                flowables.append(Paragraph(f"- Package Name: {manifest_data.get('Package Name', 'Unknown')}", custom_style))
                flowables.append(Paragraph(f"- Minimum SDK: {manifest_data.get('Minimum SDK', 'Unknown')}", custom_style))
                flowables.append(Paragraph(f"- Target SDK: {manifest_data.get('Target SDK', 'Unknown')}", custom_style))
        else:
            for key, value in overview.items():
                if value:  # Only include non-empty values
                    flowables.append(Paragraph(f"- {key}: {value}", custom_style))
        flowables.append(Spacer(1, 12))

        # Manifest Analysis
        manifest_info = data['analysis_result'].get('manifest', {})
        flowables.append(Paragraph("<b>MANIFEST ANALYSIS</b>", heading2))
        
        # If manifest data is empty or in wrong format, let's check if we can get the data directly
        if not manifest_info or not any(manifest_info.values()):
            manifest_raw = data['analysis_result'].get('manifest_analysis', {})
            if manifest_raw:
                sdk_versions = manifest_raw.get('sdk_versions', {})
                manifest_info = {
                    "Minimum SDK": sdk_versions.get('min_sdk', 'Unknown'),
                    "Target SDK": sdk_versions.get('target_sdk', 'Unknown'),
                    "Permissions": manifest_raw.get('permissions', []),
                    "Broadcast Receivers": manifest_raw.get('broadcast_receivers', []),
                    "Content Providers": manifest_raw.get('content_providers', []),
                    "Activities": manifest_raw.get('activities', []),
                    "Certificates": [f"SHA1: {cert.get('sha1', 'Unknown')}" for cert in manifest_raw.get('certificates', [])]
                }
        
        for field, value in manifest_info.items():
            if isinstance(value, list):
                if value:  # Only display if list is not empty
                    flowables.append(Paragraph(f"- {field}:", custom_style))
                    for item in value:
                        flowables.append(Paragraph(f"  * {item}", custom_style))
            elif value:  # Only display if value is not empty
                flowables.append(Paragraph(f"- {field}: {value}", custom_style))
        flowables.append(Spacer(1, 12))

        # Database Encryption
        db_info = data['analysis_result'].get('encryption', {})
        flowables.append(Paragraph("<b>DATABASE ENCRYPTION STATE</b>", heading2))
        encryption_status = db_info.get("Encryption Status", "Not Available")
        flowables.append(Paragraph(f"- Status: {encryption_status}", custom_style))
        flowables.append(Spacer(1, 12))

        # Suspicious APIs
        api_info = data['analysis_result'].get('suspicious_apis', {})
        flowables.append(Paragraph("<b>SUSPICIOUS API CALLS</b>", heading2))
        apis = api_info.get("APIs", [])
        
        # If APIs is empty, try alternate data structure
        if not apis and 'suspicious_api_calls' in data['analysis_result']:
            api_calls_data = data['analysis_result'].get('suspicious_api_calls', {})
            apis = api_calls_data.get("suspicious_apis", [])
        
        if apis:
            for api in apis:
                if isinstance(api, dict):
                    method = api.get("method", "Unknown Method")
                    description = api.get("description", "No description available.")
                    flowables.append(Paragraph(f"- Method: {method}", custom_style))
                    flowables.append(Paragraph(f"  Description: {description}", custom_style))
                elif isinstance(api, str):
                    # Handle case where it's just a string
                    flowables.append(Paragraph(f"- API: {api}", custom_style))
        else:
            flowables.append(Paragraph("- No suspicious API calls found.", custom_style))
        flowables.append(Spacer(1, 12))

        # Signature Based Analysis
        sig_info = data['analysis_result'].get('signature_analysis', {})
        flowables.append(Paragraph("<b>SIGNATURE BASED ANALYSIS</b>", heading2))
        matches = sig_info.get("Matches", [])
        
        # If no matches found, try alternative structure
        if not matches and 'signature' in data['analysis_result']:
            sig_data = data['analysis_result'].get('signature', {})
            yara_results = sig_data.get("yara_results", {})
            for category, result in yara_results.items():
                category_matches = result.get("matches", [])
                if category_matches:
                    for match in category_matches:
                        if isinstance(match, dict):
                            matches.append({
                                "file": match.get("file", "Unknown File"),
                                "rule": match.get("rule", category)
                            })
        
        if matches:
            for match in matches:
                if isinstance(match, dict):
                    filename = match.get("file", "Unknown File")
                    rule = match.get("rule", "Unnamed Rule") 
                    flowables.append(Paragraph(f"- File: {filename} matched rule: {rule}", custom_style))
                elif isinstance(match, str):
                    # Handle case where it's just a string
                    flowables.append(Paragraph(f"- Match: {match}", custom_style))
        else:
            flowables.append(Paragraph("- No YARA signature matches found.", custom_style))

        doc.build(flowables)
        return True
    except Exception as e:
        print(f"[!] PDF Report Error: {e}")
        return False


def generate_html(data, output_path):
    try:
        # Get suspicious API calls data with fallback mechanism
        api_info = data['analysis_result'].get('suspicious_apis', {})
        apis = api_info.get("APIs", [])
        if not apis and 'suspicious_api_calls' in data['analysis_result']:
            api_calls_data = data['analysis_result'].get('suspicious_api_calls', {})
            apis = api_calls_data.get("suspicious_apis", [])
            
        # Format the API data properly for the template
        formatted_apis = []
        if isinstance(apis, list):
            for api in apis:
                if isinstance(api, dict):
                    formatted_apis.append(api)
                elif isinstance(api, str):
                    formatted_apis.append({"method": api, "description": "No description available"})
        
        # Get signature analysis data with fallback mechanism
        sig_info = data['analysis_result'].get('signature_analysis', {})
        matches = sig_info.get("Matches", [])
        if not matches and 'signature' in data['analysis_result']:
            sig_data = data['analysis_result'].get('signature', {})
            yara_results = sig_data.get("yara_results", {})
            for category, result in yara_results.items():
                category_matches = result.get("matches", [])
                if category_matches:
                    for match in category_matches:
                        if isinstance(match, dict):
                            matches.append({
                                "file": match.get("file", "Unknown File"),
                                "rule": match.get("rule", category)
                            })
        
        # Format the matches data properly for the template
        formatted_matches = []
        if isinstance(matches, list):
            for match in matches:
                if isinstance(match, dict):
                    formatted_matches.append(match)
                elif isinstance(match, str):
                    formatted_matches.append({"file": "Unknown", "rule": match})
        
        # Create a dictionary of manifest data with proper formatting
        manifest_data = {}
        manifest_info = data['analysis_result'].get('manifest', {})
        for key, value in manifest_info.items():
            if value:  # Only include non-empty values
                manifest_data[key] = value
        
        # Create structured module results for the template
        module_results = {
            "Manifest Analysis": manifest_data,
            "Database Encryption": {
                "Status": data['analysis_result'].get('encryption', {}).get("Encryption Status", "Not Available")
            },
            "Suspicious API Calls": formatted_apis,
            "Signature Based Analysis": formatted_matches
        }
        
        # Get APK overview data
        apk_info = {}
        overview = data['analysis_result'].get('apk_overview', {})
        if overview:
            for key, value in overview.items():
                if value:  # Only include non-empty values
                    apk_info[key] = value
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        templates_dir = os.path.join(current_dir, "templates")
        
        env = Environment(loader=FileSystemLoader(templates_dir))
        template = env.get_template("report_template.html")

        rendered = template.render(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            tool_version="1.0.0",
            verdict=data['maliciousness_decision'].get("status", "UNKNOWN"),
            reasons=data['maliciousness_decision'].get("reasons", []),
            apk_info=apk_info,
            module_results=module_results
        )

        with open(output_path, 'w') as f:
            f.write(rendered)
        return True
    except Exception as e:
        print(f"[!] HTML Report Error: {e}")
        import traceback
        print(traceback.format_exc())  # Print the full traceback for better debugging
        return False
