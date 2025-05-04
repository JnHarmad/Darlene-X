# forensipie/modules/apk_unpack_decompile.py

import os
import zipfile
from androguard.misc import AnalyzeAPK
from loguru import logger
import traceback

logger.remove()


def apk_unpack_and_decompile(apk_path, base_output_dir):
    """
    Unpacks the APK, extracts DEX info, and returns structured results.
    """
    results = {
        "apk_file": apk_path,
        "output_dir": base_output_dir,
        "dex_files": [],
        "status": "Success",
        "Classes": 0,  # Initialize class count
        "Methods": 0,  # Initialize method count
        "Errors": []
    }

    try:
        a, d, dx = AnalyzeAPK(apk_path)

        # Extract basic APK info
        try:
            os.makedirs(base_output_dir, exist_ok=True)
            with zipfile.ZipFile(apk_path, "r") as apk_zip:
                apk_zip.extractall(base_output_dir)
            logger.info(f"📂 APK contents extracted to: {base_output_dir}\n")
        except Exception as extract_error:
            results["Errors"].append(f"Error extracting APK: {str(extract_error)}")

        # Process DEX files
        total_classes = 0
        total_methods = 0
        
        if not d:  # If no DEX files found
            results["Errors"].append("No DEX files found in the APK")
        else:
            # Process each DEX file
            for i, dex in enumerate(d, start=1):
                dex_dir = os.path.join(base_output_dir, f"dex_{i}")
                os.makedirs(dex_dir, exist_ok=True)

                class_data = []
                dex_class_count = 0
                dex_method_count = 0
                
                # Process classes in the DEX
                for cls in dex.get_classes():
                    methods = cls.get_methods()
                    dex_class_count += 1
                    dex_method_count += len(methods)
                    
                    # Store detailed class info
                    class_info = {
                        "class_name": cls.get_name(),
                        "methods": [
                            {
                                "method_name": m.get_name(),
                                "descriptor": m.get_descriptor()
                            } for m in methods
                        ]
                    }
                    class_data.append(class_info)

                # Increment total counts
                total_classes += dex_class_count
                total_methods += dex_method_count

                # Store DEX file info
                dex_result = {
                    "dex_file": f"dex_{i}",
                    "classes": class_data,
                    "class_count": dex_class_count,
                    "method_count": dex_method_count,
                    "output_path": dex_dir
                }
                results["dex_files"].append(dex_result)

            # Update total counts in the results
            results["Classes"] = total_classes
            results["Methods"] = total_methods
            
            logger.success(f"✅ Processed {len(d)} DEX files with {total_classes} classes and {total_methods} methods\n")

        logger.success("✅ APK unpacking and DEX processing completed.\n")

    except Exception as e:
        error_msg = f"Error during unpacking: {str(e)}"
        results["status"] = "Failed"
        results["error"] = error_msg
        results["Errors"].append(error_msg)
        results["Errors"].append(traceback.format_exc())
        logger.error(f"❌ {error_msg}")

    return results

def analyze_apk_unpack(apk_path):
    if not os.path.exists(apk_path):
        return {
            "status": "Failed", 
            "error": f"APK file not found: {apk_path}",
            "Classes": 0,
            "Methods": 0,
            "Errors": [f"APK file not found: {apk_path}"]
        }, None
        
    output_dir = os.path.join(os.path.dirname(apk_path), "unpacked_output")
    results = apk_unpack_and_decompile(apk_path, output_dir)
    
    # Ensure class and method counts are properly set
    if results.get("Classes", 0) == 0 and results.get("dex_files", []):
        # Calculate class and method counts if not already set
        class_count = 0
        method_count = 0
        for dex_file in results.get("dex_files", []):
            class_count += len(dex_file.get("classes", []))
            for cls in dex_file.get("classes", []):
                method_count += len(cls.get("methods", []))
        
        # Add both top-level and capitalized key versions to ensure compatibility
        results["Classes"] = class_count
        results["Methods"] = method_count
        results["classes"] = class_count
        results["methods"] = method_count
    
    # Store the console output message for fallback
    if results.get("Classes", 0) > 0 and results.get("Methods", 0) > 0:
        console_output = f"APK unpacking completed with {results['Classes']} classes and {results['Methods']} methods."
        results["console_output"] = [console_output]
    
    return results, output_dir  # returns both unpack results and dir path