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
                results[results_key] = analyze_func(apk_path)
            except Exception as e:
                console.print(f"[red]Error running {module_name}: {e}[/red]")
    return results

def decide_maliciousness(apk_path: str) -> dict:
    all_results = gather_all_analysis(apk_path)

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