# forensipie/test/test_unpack.py

if __name__ == "__main__":
    from tkinter import Tk, filedialog
    from pathlib import Path
    from forensipie.modules.apk_unpack_decompile import analyze_apk_unpack

    root = Tk()
    root.withdraw()

    apk_path = filedialog.askopenfilename(
        title="Select APK File",
        filetypes=[("APK Files", "*.apk")]
    )

    if not apk_path:
        print("No APK selected. Exiting.")
        exit()

    # No need to specify output dir, it's calculated within the function
    print(f"Selected APK: {apk_path}\n")

    results = analyze_apk_unpack(apk_path)

    # Print summary
    print("\n--- Result Summary ---")
    print(f"Classes: {results['statistics']['total_classes']}")
    print(f"Methods: {results['statistics']['total_methods']}")
    print(f"DEX Files: {results['statistics']['dex_count']}")
    
    if results["errors"]:
        print("Errors:")
        for error in results["errors"]:
            print(f"- {error}")
