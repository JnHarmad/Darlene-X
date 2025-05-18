import sys
import importlib
from rich.console import Console

console = Console()

MODULES_TO_ANALYZE = [
    "apk_unpack_decompile",
    "manifest_analysis",
    "encryption_state_db",
    "suspicious_api_calls",
    "signature_analysis"
]

def import_analysis_function(module_name):
    try:
        module = importlib.import_module(f"forensipie.modules.{module_name}")
        for attr in dir(module):
            if attr.startswith("analyze_"):
                return getattr(module, attr)
    except Exception as e:
        console.print(f"[red]Error importing {module_name}: {e}[/red]")
        return None

def gather_all_analysis(apk_path: str) -> dict:
    results = {}
    for module_name in MODULES_TO_ANALYZE:
        analyze_func = import_analysis_function(module_name)
        if analyze_func:
            results_key = module_name.split('_analysis')[0]
            try:
                # Special handling for apk_unpack_decompile which returns a single value now
                if module_name == "apk_unpack_decompile":
                    try:
                        # Updated to handle single return value
                        module_result = analyze_func(apk_path)
                        results[results_key] = module_result
                        
                        # Add debug info about the unpacked data
                        classes = module_result.get('statistics', {}).get('total_classes', 0)
                        methods = module_result.get('statistics', {}).get('total_methods', 0)
                        
                        # Map the new structure to the old structure for compatibility
                        if 'statistics' in module_result:
                            # Create Classes and Methods fields for compatibility
                            module_result['Classes'] = classes
                            module_result['Methods'] = methods
                        
                        if module_result.get('errors', []):
                            console.print(f"[red]APK unpacking had errors:[/red]")
                            for err in module_result.get('errors', []):
                                console.print(f"[red]Error detail: {err}[/red]")
                    except Exception as e:
                        console.print(f"[red]Exception during APK unpacking: {str(e)}[/red]")
                        import traceback
                        console.print(f"[red]{traceback.format_exc()}[/red]")
                        results[results_key] = {
                            "status": "Failed",
                            "error": str(e),
                            "Classes": 0,
                            "Methods": 0,
                            "Errors": [str(e)]
                        }
                else:
                    module_results = analyze_func(apk_path)
                    results[results_key] = module_results
                
                # Special processing for apk_overview data
                if results_key == "manifest":
                    # Create APK overview from manifest data if not already present
                    if "apk_overview" not in results:
                        results["apk_overview"] = {
                            "File Name": apk_path,
                            "File Path": apk_path,
                            "Package Name": module_results.get("package_name", "Unknown"),
                            "Minimum SDK": module_results.get("sdk_versions", {}).get("min_sdk", "Unknown"),
                            "Target SDK": module_results.get("sdk_versions", {}).get("target_sdk", "Unknown")
                        }
                
                # If we have apk_unpack data with overview, use it to update or create APK overview
                if results_key == "apk_unpack" and "overview" in module_results:
                    overview = module_results.get("overview", {})
                    
                    # Create APK overview if not already present
                    if "apk_overview" not in results:
                        results["apk_overview"] = {}
                    
                    # Update with more detailed overview from unpack module
                    results["apk_overview"].update({
                        "File Name": apk_path,
                        "File Path": apk_path,
                        "Package Name": overview.get("package_name", results["apk_overview"].get("Package Name", "Unknown")),
                        "Minimum SDK": overview.get("sdk_version", results["apk_overview"].get("Minimum SDK", "Unknown")),
                        "File Size": overview.get("file_size", "Unknown"),
                        "SHA-256": overview.get("file_hash", "Unknown")
                    })
                
                # Standardize manifest data format for report if we're processing manifest results
                if results_key == "manifest":
                    results["manifest"] = {
                        "Minimum SDK": module_results.get("sdk_versions", {}).get("min_sdk", "Unknown"),
                        "Target SDK": module_results.get("sdk_versions", {}).get("target_sdk", "Unknown"),
                        "Permissions": module_results.get("permissions", []),
                        "Broadcast Receivers": module_results.get("broadcast_receivers", []),
                        "Content Providers": module_results.get("content_providers", []),
                        "Activities": module_results.get("activities", []),
                        "Certificates": [f"SHA1: {cert.get('sha1', 'Unknown')}" for cert in module_results.get("certificates", [])]
                    }
                
                # Standardize suspicious API calls data format
                elif results_key == "suspicious_api_calls":
                    suspicious_apis = module_results.get("suspicious_apis", [])
                    # Create both keys to ensure compatibility
                    results["suspicious_api_calls"] = module_results
                    results["suspicious_apis"] = {
                        "APIs": suspicious_apis if isinstance(suspicious_apis, list) else []
                    }
                
                # Standardize signature analysis data format
                elif results_key == "signature":
                    # Create standardized format for signature analysis
                    results["signature_analysis"] = {
                        "Matches": []
                    }
                    
                    # Extract YARA matches if they exist
                    yara_results = module_results.get("yara_results", {})
                    for category, result in yara_results.items():
                        matches = result.get("matches", [])
                        if matches and isinstance(matches, list):
                            for match in matches:
                                results["signature_analysis"]["Matches"].append({
                                    "file": match.get("file", "Unknown"),
                                    "rule": match.get("rule", category)
                                })
                
            except Exception as e:
                console.print(f"[red]Error running {module_name}: {e}[/red]")
    return results

def decide_maliciousness(apk_path: str, precomputed_results: dict = None) -> dict:
    # If precomputed_results is passed, use it. Otherwise, gather all analysis results.
    all_results = precomputed_results if precomputed_results else gather_all_analysis(apk_path)

    decision = {
        "status": "SAFE",
        "reasons": []
    }

    try:
        # === Manifest Analysis Check ===
        manifest = all_results.get("manifest", {})
        permissions = manifest.get("permissions", [])
        receivers = manifest.get("broadcast_receivers", [])
        certificates = manifest.get("certificates", [])
        sdk_versions = manifest.get("sdk_versions", {})

        dangerous_permissions = [
            "SEND_SMS", "READ_SMS", "RECEIVE_SMS", "READ_CONTACTS", 
            "WRITE_CONTACTS", "RECEIVE_BOOT_COMPLETED", "SYSTEM_ALERT_WINDOW"
        ]

        if any(perm.split('.')[-1] in dangerous_permissions for perm in permissions):
            decision["reasons"].append("Dangerous Permissions Detected")

        if len(receivers) > 5:
            decision["reasons"].append("Multiple Broadcast Receivers Detected")

        if not certificates:
            decision["reasons"].append("Missing or Suspicious Certificates")

        if sdk_versions and int(sdk_versions.get("target_sdk", 0) or 0) < 16:
            decision["reasons"].append("Target SDK Version is very old")

        # === Encryption State Check ===
        encryption = all_results.get("encryption_state_db", {})
        databases = encryption.get("databases", [])
        for db in databases:
            if db.get("encryption_status") in ["not_encrypted", "corrupted"]:
                decision["reasons"].append(f"Database {db.get('path')} is {db.get('encryption_status')}")

        # === Suspicious API Calls Check ===
        suspicious_api = all_results.get("suspicious_api_calls", {})
        if suspicious_api.get("suspicious_apis"):
            decision["reasons"].append("Suspicious API Calls Detected")

        # === YARA Signature Analysis Check ===
        signature = all_results.get("signature", {})
        yara_results = signature.get("yara_results", {})
        for category, result in yara_results.items():
            if result.get("matches_found", False):
                decision["reasons"].append(f"YARA Match Found: {category.replace('_', ' ').title()}")

        # === APK Unpack Check ===
        unpack = all_results.get("apk_unpack", {})
        dex_files = unpack.get("dex_files", [])
        if len(dex_files) > 4:
            decision["reasons"].append("Excessive Number of DEX Files Detected")

        # === Final Status ===
        if decision["reasons"]:
            decision["status"] = "MALICIOUS"

    except Exception as e:
        decision["status"] = "Error"
        decision["error"] = str(e)
        console.print(f"[red]Error during maliciousness decision: {e}[/red]")

    return decision
