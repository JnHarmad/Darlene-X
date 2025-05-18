# forensipie/modules/apk_unpack_decompile.py

import os
import zipfile
import hashlib
import json
import traceback
from loguru import logger
from androguard.misc import AnalyzeAPK
from pathlib import Path

logger.remove()

def analyze_apk_unpack(apk_path):
    """
    Analyzes an APK and generates:
    - On-screen report (metadata + statistics)
    - output_unpack/: Extracted APK contents
    - output_decompiled/: Decompiled class/method data
    """
    
    if not apk_path.lower().endswith('.apk') or not os.path.exists(apk_path):
        raise FileNotFoundError(f"Invalid or missing APK file: {apk_path}")

    # --- Initialize results ---
    results = {
        "overview": {
            "apk_name": os.path.basename(apk_path),
            "file_size": f"{os.path.getsize(apk_path) / 1024:.2f} KB",
            "file_hash": None,
            "sdk_version": None,
            "package_name": None,
        },
        "statistics": {
            "total_classes": 0,
            "total_methods": 0,
            "dex_count": 0
        },
        "components": {
            "unpacked_files": [],
            "decompiled_classes": []
        },
        "errors": []
    }

    # --- Common: AnalyzeAPK parsed once ---
    try:
        a, d, dx = AnalyzeAPK(apk_path)
    except Exception as e:
        results["errors"].append(f"APK analysis failed: {str(e)}")
        print("\n[Errors]")
        print(f"⚠️  APK analysis failed: {str(e)}")
        return results  # Skip rest of analysis if base parsing fails

    # --- Phase 1: APK Metadata ---
    try:
        with open(apk_path, 'rb') as f:
            sha256_hash = hashlib.sha256(f.read()).hexdigest()
            results["overview"]["file_hash"] = sha256_hash

        results["overview"]["sdk_version"] = a.get_effective_target_sdk_version()
        results["overview"]["package_name"] = a.get_package()
    except Exception as e:
       print("\n[Traceback for APK Metadata/AnalyzeAPK error]")
       traceback.print_exc()  # 👈 This prints exact file, line, error
       results["errors"].append(f"Metadata extraction failed: {str(e)}")
       return results  # Optionally stop further processing if this fails
    
    # --- Phase 2: Unpack APK ---
    # Find the forensipie directory (where the code is running from)
    forensipie_dir = Path(__file__).resolve().parents[2]  # Go up to the ForensiPie root
    output_base_dir = forensipie_dir / "output"
    
    # Create apk-specific subfolder using hash to avoid name conflicts
    apk_name = os.path.splitext(os.path.basename(apk_path))[0]
    apk_hash = sha256_hash[:10]  # Use first 10 chars of hash for uniqueness
    output_subdir = f"{apk_name}_{apk_hash}"
    
    # Create directories
    unpack_dir = os.path.join(output_base_dir, output_subdir, "unpacked")
    os.makedirs(unpack_dir, exist_ok=True)

    try:
        with zipfile.ZipFile(apk_path, 'r') as apk_zip:
            apk_zip.extractall(unpack_dir)
            results["components"]["unpacked_files"] = [
                f for f in os.listdir(unpack_dir) if not f.startswith('.')
            ]
    except Exception as e:
        results["errors"].append(f"Unpacking failed: {str(e)}")

    # --- Phase 3: Decompile & Analyze ---
    decompile_dir = os.path.join(output_base_dir, output_subdir, "decompiled")
    os.makedirs(decompile_dir, exist_ok=True)

    try:
        results["statistics"]["dex_count"] = len(d)

        for dex_idx, dex in enumerate(d, start=1):
            dex_data = {
                "dex_name": f"classes{dex_idx}.dex",
                "classes": []
            }

            for cls in dex.get_classes():
                methods = cls.get_methods()
                class_info = {
                    "name": cls.get_name(),
                    "method_count": len(methods)
                }
                dex_data["classes"].append(class_info)
                results["statistics"]["total_classes"] += 1
                results["statistics"]["total_methods"] += len(methods)

            # Save decompiled data per DEX
            dex_output_path = os.path.join(decompile_dir, f"dex_{dex_idx}.json")
            with open(dex_output_path, 'w', encoding='utf-8') as f:
                json.dump(dex_data, f, indent=2)

            results["components"]["decompiled_classes"].append(dex_output_path)

    except Exception as e:
        results["errors"].append(f"Decompilation failed: {str(e)}")

    # --- Generate On-Screen Report ---
    print("\n=== UNPACK & DECOMPILED REPORT ===")
    print(f"\n[Overview]")
    print(f"Apk Name: {results['overview']['apk_name']}")
    print(f"File Size: {results['overview']['file_size']}")
    print(f"SHA-256 Hash: {results['overview']['file_hash']}")
    print(f"Sdk Version: {results['overview']['sdk_version']}")
    print(f"Package Name: {results['overview']['package_name']}")

    print(f"\n[Statistics]")
    print(f"DEX Files: {results['statistics']['dex_count']}")
    print(f"Total Classes: {results['statistics']['total_classes']}")
    print(f"Total Methods: {results['statistics']['total_methods']}")

    if results["errors"]:
        print("\n[Errors]")
        for error in results["errors"]:
            print(f"⚠️  {error}")

    # Add output paths for display in the report
    print(f"\n[Output Paths]")
    print(f"Unpacked APK: {os.path.abspath(unpack_dir)}")
    print(f"Decompiled Data: {os.path.abspath(decompile_dir)}")

    # Add output paths to results for reference in other modules
    results["output_paths"] = {
        "unpack_dir": unpack_dir,
        "decompile_dir": decompile_dir
    }

    # Add legacy fields for backward compatibility with existing reporting
    results["Classes"] = results["statistics"]["total_classes"]
    results["Methods"] = results["statistics"]["total_methods"]
    results["dex_files"] = ["classes{}.dex".format(i+1) for i in range(results["statistics"]["dex_count"])]
    results["Errors"] = results["errors"]

    return results
