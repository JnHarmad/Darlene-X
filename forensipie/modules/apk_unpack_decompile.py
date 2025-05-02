# forensipie/modules/apk_unpack_decompile.py

import os
import zipfile
from androguard.misc import AnalyzeAPK
from loguru import logger

logger.remove()


def apk_unpack_and_decompile(apk_path, base_output_dir):
    """
    Unpacks the APK, extracts DEX info, and returns structured results.
    """
    results = {
        "apk_file": apk_path,
        "output_dir": base_output_dir,
        "dex_files": [],
        "status": "Success"
    }

    try:
        a, d, dx = AnalyzeAPK(apk_path)

        os.makedirs(base_output_dir, exist_ok=True)

        with zipfile.ZipFile(apk_path, "r") as apk_zip:
            apk_zip.extractall(base_output_dir)
        logger.info(f"📂 APK contents extracted to: {base_output_dir}\n")

        for i, dex in enumerate(d, start=1):
            dex_dir = os.path.join(base_output_dir, f"dex_{i}")
            os.makedirs(dex_dir, exist_ok=True)

            class_data = []
            for cls in dex.get_classes():
                class_info = {
                    "class_name": cls.get_name(),
                    "methods": [
                        {
                            "method_name": m.get_name(),
                            "descriptor": m.get_descriptor()
                        } for m in cls.get_methods()
                    ]
                }
                class_data.append(class_info)

            dex_result = {
                "dex_file": f"dex_{i}",
                "classes": class_data,
                "output_path": dex_dir
            }
            results["dex_files"].append(dex_result)

        logger.success("✅ APK unpacking and DEX processing completed.\n")

    except Exception as e:
        logger.error(f"❌ Error during unpacking: {e}")
        results["status"] = "Failed"
        results["error"] = str(e)

    return results

def analyze_apk_unpack(apk_path):
    output_dir = os.path.join(os.path.dirname(apk_path), "unpacked_output")
    results = apk_unpack_and_decompile(apk_path, output_dir)
    return results, output_dir  # ← now returns both unpack results and dir path