# darlene_x/modules/encryption_state_db.py

from androguard.misc import AnalyzeAPK
import os
import zipfile
import sqlite3
from loguru import logger

logger.remove()


SQLITE_HEADER = b"SQLite format 3\x00"
HEADER_SIZE = len(SQLITE_HEADER)

def is_database_encrypted(db_path: str) -> str:
    """
    Determines if a SQLite database is encrypted, corrupted, or not encrypted.
    """
    try:
        if not os.path.isfile(db_path):
            return "not_found"

        with open(db_path, "rb") as f:
            header = f.read(HEADER_SIZE)
            if header != SQLITE_HEADER:
                return "encrypted"

        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            _ = cursor.fetchall()
            conn.close()
            return "not_encrypted"
        except sqlite3.DatabaseError:
            return "corrupted"

    except Exception:
        return "corrupted"


def analyze_encryption_posture(apk_path: str, extract_dir: str) -> dict:
    """
    Analyzes already extracted APK contents to find SQLite databases and assess their encryption status.
    Returns structured results.
    """
    result = {
        "apk_file": apk_path,
        "databases": [],
        "status": "Success"
    }

    try:
        AnalyzeAPK(apk_path)  # Validation only

        # ✅ Skip re-extraction — we assume files already unpacked to extract_dir
        if not os.path.exists(extract_dir) or not os.listdir(extract_dir):
            raise FileNotFoundError(f"Expected extracted contents not found in {extract_dir}")

        for root, _, files in os.walk(extract_dir):
            for file in files:
                if file.endswith(".db") or file.endswith(".sqlite"):
                    db_path = os.path.join(root, file)
                    status = is_database_encrypted(db_path)
                    result["databases"].append({
                        "path": db_path,
                        "encryption_status": status
                    })

        if not result["databases"]:
            result["warning"] = "No database files found."

    except Exception as e:
        result["status"] = "Failed"
        result["error"] = str(e)

    return result


# ✅ Standardized entry point
# NEW
def analyze_encryption(apk_path):
    base_dir = os.path.dirname(apk_path)
    extract_dir = os.path.join(base_dir, "extracted_contents")
    return analyze_encryption_posture(apk_path, extract_dir)
