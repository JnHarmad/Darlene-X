# darlene_x/modules/manifest_analysis.py

from androguard.misc import AnalyzeAPK
import hashlib
from loguru import logger

logger.remove()


def analyze_manifest_and_certificate(apk_path: str) -> dict:
    """
    Analyzes manifest and certificates, returns structured results.
    """
    result = {
        "apk_file": apk_path,
        "package_name": None,
        "sdk_versions": {},
        "permissions": [],
        "activities": [],
        "broadcast_receivers": [],
        "content_providers": [],
        "certificates": [],
        "status": "Success"
    }

    try:
        a, d, dx = AnalyzeAPK(apk_path)
        result["package_name"] = a.get_package()

        result["sdk_versions"] = {
            "min_sdk": a.get_min_sdk_version(),
            "target_sdk": a.get_target_sdk_version(),
            "max_sdk": a.get_max_sdk_version()
        }

        result["permissions"] = a.get_permissions()
        result["activities"] = a.get_activities()
        result["broadcast_receivers"] = a.get_receivers()
        result["content_providers"] = a.get_providers()

        for cert in a.get_certificates():
            cert_data = cert.dump()
            result["certificates"].append({
                "md5": hashlib.md5(cert_data).hexdigest(),
                "sha1": hashlib.sha1(cert_data).hexdigest(),
                "sha256": hashlib.sha256(cert_data).hexdigest()
            })

    except Exception as e:
        logger.error(f"❌ Error analyzing manifest: {e}")
        result["status"] = "Failed"
        result["error"] = str(e)

    return result

# ✅ Standardized entry point
def analyze_manifest(apk_path):
    return analyze_manifest_and_certificate(apk_path)