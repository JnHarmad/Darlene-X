from report_generator import generate_reports
import os

dummy_data = {
    "apk_file": "sample.apk",
    "analysis_timestamp": "2025-04-24 15:45:00",
    "sections": {
        "permissions": ["android.permission.INTERNET", "android.permission.CAMERA"],
        "sdk_versions": {"min_sdk": "21", "target_sdk": "33"},
        "suspicious_apis": [
            {"method": "onCreate", "api_call": "Ljava/lang/Runtime;->exec", "description": "Potential command execution"}
        ],
        "databases": [
            {"path": "/data/data/sample.db", "encryption_status": "not_encrypted"}
        ],
        "certificates": [
            {"md5": "abc123...", "sha1": "def456...", "sha256": "ghi789..."}
        ]
    }
}

output_dir = os.path.join(os.getcwd(), "test_reports")

os.makedirs(output_dir, exist_ok=True)

result = generate_reports(dummy_data, output_dir)
print("\n📝 Test Report Paths:")
print(result)
