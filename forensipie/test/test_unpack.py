# forensipie/test/test_unpack.py

if __name__ == "__main__":
    from tkinter import Tk, filedialog
    from pathlib import Path
    from forensipie.modules.apk_unpack_decompile import apk_unpack_and_decompile

    root = Tk()
    root.withdraw()

    apk_path = filedialog.askopenfilename(
        title="Select APK File",
        filetypes=[("APK Files", "*.apk")]
    )

    if not apk_path:
        print("No APK selected. Exiting.")
        exit()

    root_path = Path(__file__).resolve().parents[2]  # Go back to FORENSIPIE/
    output_dir = root_path / "apk_output"

    print(f"Selected APK: {apk_path}")
    print(f"Output Directory: {output_dir}\n")

    results = apk_unpack_and_decompile(apk_path, str(output_dir))

    # Print summary
    print("\n--- Result Summary ---")
    print(f"DEX Files Processed: {len(results['dex_files'])}")
    if results["status"] == "Failed":
        print("Error:", results["error"])
