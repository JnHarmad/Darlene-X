import os
from tkinter import Tk, filedialog
from forensipie.modules.signature_analysis import analyze_apk_signature

def select_apk_and_analyze():
    # Create Tkinter root window (hidden)
    root = Tk()
    root.withdraw()

    # Open file dialog to select the APK file
    apk_path = filedialog.askopenfilename(
        title="Select APK File",
        filetypes=[("APK Files", "*.apk")]
    )

    if not apk_path:
        print("No APK file selected. Exiting.")
        return

    # Perform the analysis using the selected APK file
    print(f"Selected APK: {apk_path}")
    print("Starting Signature Analysis...")

    # Call the analyze_apk_signature function
    results = analyze_apk_signature(apk_path)

    # Print the results
    print("\n" + "=" * 60)
    print("🧪 YARA Scan Summary")
    print("=" * 60)
    print(f"📄 APK File: {os.path.basename(apk_path)}")
    print(f"🕒 Analysis Timestamp: {results['analysis_timestamp']}")
    print("=" * 60)

    # Display the analysis results
    for category, result in results['yara_results'].items():
        emoji = {
            "boot_persistency": "✅",
            "hidden_payloads": "🔍",
            "obfuscation": "🕵️"
        }.get(category, "ℹ️")

        print(f"\n{emoji} {category.replace('_', ' ').title()} Check")
        if result['matches_found']:
            print("⚠️ Matches Found:")
            for match in result['matches']:
                print(f"  📄 File: {match['file']}")
                print(f"     └─ Rules Triggered: {match['matches']}")
        else:
            print(f"  ✅ No {category.replace('_', ' ')} indicators found.")
    print("=" * 60)

if __name__ == "__main__":
    select_apk_and_analyze()
