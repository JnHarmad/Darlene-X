# darlene_x/modules/suspicious_api_calls.py

from androguard.misc import AnalyzeAPK
from loguru import logger
from datetime import datetime
import os

logger.remove()


SUSPICIOUS_APIS = {
    "Ljava/net/HttpURLConnection;": "Potential network communication.",
    "Ljavax/crypto/Cipher;": "Potential cryptographic operation.",
    "Ljava/lang/Runtime;->exec": "Potential command execution.",
    "Landroid/telephony/SmsManager;->sendTextMessage": "Potential SMS sending activity.",
    "Landroid/content/ContentResolver;->query": "Potential database query operation.",
}


def detect_suspicious_api_calls(apk_path: str) -> dict:
    """
    Analyzes APK and detects suspicious API calls based on static analysis.

    Returns:
        dict: Structured report of detected suspicious APIs.
    """
    result = {
        "apk_file": apk_path,
        "timestamp": datetime.now().isoformat(),
        "suspicious_apis": [],
        "status": "Success"
    }

    try:
        a, d, dx = AnalyzeAPK(apk_path)
        for method in dx.get_methods():
            for _, call, _ in method.get_xref_to():
                if any(api in str(call) for api in SUSPICIOUS_APIS):
                    method_name = method.method.get_name()
                    class_call = f"{call.class_name}->{call.name}"
                    description = next((desc for api, desc in SUSPICIOUS_APIS.items() if api in str(call)), "Unknown usage.")
                    result["suspicious_apis"].append({
                        "method": method_name,
                        "api_call": class_call,
                        "description": description
                    })

    except Exception as e:
        result["status"] = "Failed"
        result["error"] = str(e)

    return result


def print_api_report(result: dict):
    """
    Pretty prints the suspicious API call report.
    """
    def truncate(text, width): return (text[:width - 3] + "...") if len(text) > width else text

    print("\n" + "=" * 80)
    print("🔍 APK Static Code Analysis Report")
    print("=" * 80)
    print(f"📄 APK File: {os.path.basename(result['apk_file'])}")
    print(f"🕒 Analysis Timestamp: {result['timestamp']}")
    print(f"🚨 Total Suspicious API Calls Detected: {len(result['suspicious_apis'])}\n")

    if not result["suspicious_apis"]:
        print("✅ No suspicious API calls were detected.\n")
        return

    print("=== Suspicious API Calls ===")  
    print(f"{'Method Name':<45} {'API Call':<60} Description")
    print("-" * 140)

    for entry in result["suspicious_apis"]:
        print(f"{truncate(entry['method'], 45):<45} {truncate(entry['api_call'], 60):<60} {entry['description']}")

    print("=" * 80 + "\n")

# ✅ Standardized entry point
def analyze_suspicious_apis(apk_path):
    return detect_suspicious_api_calls(apk_path)