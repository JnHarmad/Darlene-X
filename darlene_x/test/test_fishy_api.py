# darlene_x/test/test_suspicious_api_calls.py

from tkinter import Tk, filedialog
from darlene_x.modules.suspicious_api_calls import detect_suspicious_api_calls, print_api_report

if __name__ == "__main__":
    root = Tk()
    root.withdraw()

    apk_path = filedialog.askopenfilename(
        title="Select APK File",
        filetypes=[("APK Files", "*.apk")]
    )

    if not apk_path:
        print("No APK file selected. Exiting.")
        exit()

    report = detect_suspicious_api_calls(apk_path)
    print_api_report(report)
