# forensipie/test/test_encryption_state.py

from tkinter import Tk, filedialog
from forensipie.modules.encryption_state_db import analyze_encryption_posture
from pprint import pprint
import os
import sys

from loguru import logger
logger.remove()
logger.add(sys.stderr, level="DEBUG")

def main():
    root = Tk()
    root.withdraw()

    apk_path = filedialog.askopenfilename(
        title="Select APK File",
        filetypes=[("APK Files", "*.apk")]
    )

    if not apk_path:
        print("No APK file selected. Exiting.")
        return

    output_dir = os.path.join(os.getcwd(), "apk_output_db")

    result = analyze_encryption_posture(apk_path, output_dir)

    print("\n--- Encryption Posture Report ---")
    pprint(result)

if __name__ == "__main__":
    main()
