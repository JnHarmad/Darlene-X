# forensipie/test/test_manifest.py

if __name__ == "__main__":
    from tkinter import Tk, filedialog
    from forensipie.modules.manifest_analysis import analyze_manifest_and_certificate
    from pprint import pprint

    root = Tk()
    root.withdraw()

    apk_path = filedialog.askopenfilename(
        title="Select APK File",
        filetypes=[("APK Files", "*.apk")]
    )

    if not apk_path:
        print("No APK file selected. Exiting.")
        exit()

    results = analyze_manifest_and_certificate(apk_path)

    print("\n--- Manifest Analysis Report ---")
    if results["status"] == "Failed":
        print("❌ Analysis Failed:", results.get("error", "Unknown error"))
    else:
        pprint(results)
