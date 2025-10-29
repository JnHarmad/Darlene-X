import os
import sys
import tempfile
import shutil
import zipfile
import yara
from datetime import datetime
from loguru import logger

# === LOGGER SETUP ===
logger.remove()


# === CONSTANTS ===
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
YARA_RULES_PATH = os.path.join(SCRIPT_DIR, '..', 'scripts', 'yara_rules')

RULE_FILES = {
    'boot_persistency': os.path.join(YARA_RULES_PATH, 'boot_persistency.yar'),
    'hidden_payloads': os.path.join(YARA_RULES_PATH, 'hidden_payloads.yar'),
    'obfuscation': os.path.join(YARA_RULES_PATH, 'obfuscation.yar')
}

# === FUNCTIONS ===
def compile_yara_rules():
    """
    Compiles the YARA rules into an easily usable format.
    Returns a dictionary of compiled rules.
    """
    compiled_rules = {}
    for name, path in RULE_FILES.items():
        if not os.path.exists(path):
            logger.error(f"Missing YARA rule: {path}")
            continue
        try:
            compiled_rules[name] = yara.compile(filepath=path)
            logger.info(f"Compiled rule: {name}")
        except yara.SyntaxError as e:
            logger.error(f"Syntax error in {name}: {e}")
    return compiled_rules

def decompile_apk(apk_path):
    """
    Extracts APK contents to a temporary directory.
    Returns the path to the temporary directory containing the extracted APK files.
    """
    temp_dir = tempfile.mkdtemp(prefix="apk_decompiled_")
    try:
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        logger.success(f"APK extracted to: {temp_dir}")
        return temp_dir
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
        shutil.rmtree(temp_dir)
        return None

def scan_with_yara(decompiled_path, compiled_rules):
    """
    Scans the decompiled APK directory with the compiled YARA rules.
    Returns a dictionary of scan results categorized by rule.
    """
    results = {key: [] for key in RULE_FILES}

    for category, rule in compiled_rules.items():
        if rule is None:
            continue

        for root, _, files in os.walk(decompiled_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    matches = rule.match(filepath=file_path)
                    if matches:
                        results[category].append({
                            'file': file_path,
                            'matches': [match.rule for match in matches]
                        })
                except Exception as e:
                    logger.warning(f"Error scanning {file_path} with {category}: {e}")
    return results

from androguard.misc import AnalyzeAPK

def analyze_apk_signature(apk_path):
    result = {
        'apk_file': apk_path,
        'analysis_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'yara_results': {}
    }

    try:
        # Validate APK using Androguard v4+
        try:
            a, d, dx = AnalyzeAPK(apk_path)
            if a is None or a.get_package() is None:
                raise ValueError("APK appears to be invalid or corrupted.")
        except Exception as e:
            result['status'] = 'Failed'
            result['error'] = f'Invalid APK: {e}'
            return result

        compiled_rules = compile_yara_rules()
        decompiled_path = decompile_apk(apk_path)
        if not decompiled_path:
            result['status'] = 'Failed'
            result['error'] = 'APK extraction failed.'
            return result

        yara_results = scan_with_yara(decompiled_path, compiled_rules)

        for category, matches in yara_results.items():
            result['yara_results'][category] = {
                'matches_found': len(matches) > 0,
                'matches': matches
            }

        result['status'] = 'Success'

    except Exception as e:
        logger.error(f"Error during signature analysis: {e}")
        result['status'] = 'Failed'
        result['error'] = str(e)

    return result



# ✅ Standardized entry point
def analyze_signature(apk_path):
    return analyze_apk_signature(apk_path)