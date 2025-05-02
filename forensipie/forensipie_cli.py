
import os
import time
import sys
from rich.console import Console
from forensipie.modules.banner_display import show_banner
from forensipie.modules.usb_connection import run_usb_device_operations, upload_apk_via_dialog
from forensipie.modules.apk_unpack_decompile import analyze_apk_unpack
from forensipie.modules.manifest_analysis import analyze_manifest
from forensipie.modules.encryption_state_db import analyze_encryption
from forensipie.modules.suspicious_api_calls import analyze_suspicious_apis
from forensipie.modules.signature_analysis import analyze_signature
from forensipie.modules.decide_malicious import decide_maliciousness
from forensipie.modules.report_generator import generate_reports
from progress.bar import Bar

console = Console()

def show_progress_bar(task_name):
    bar = Bar(task_name, max=100)
    for _ in range(100):
        time.sleep(0.01)
        bar.next()
    bar.finish()

def run_all_analyses(apk_path):
    results = {}

    base_dir = os.path.dirname(apk_path)
    extract_dir = os.path.join(base_dir, "extracted_contents")
    os.makedirs(extract_dir, exist_ok=True)

    console.print("\n[bold cyan]Running APK Unpack and Decompile...[/bold cyan]")
    show_progress_bar("APK Unpack and Decompile")
    apk_unpack_result, extract_dir = analyze_apk_unpack(apk_path)
    results["apk_unpack_decompile"] = apk_unpack_result

    console.print("\n[bold cyan]Running Manifest Analysis...[/bold cyan]")
    show_progress_bar("Manifest Analysis")
    results["manifest_analysis"] = analyze_manifest(apk_path)

    console.print("\n[bold cyan]Running Database Encryption Analysis...[/bold cyan]")
    show_progress_bar("Database Encryption Analysis")
    results["encryption_state_db"] = analyze_encryption(apk_path)

    console.print("\n[bold cyan]Running Suspicious API Analysis...[/bold cyan]")
    show_progress_bar("Suspicious API Analysis")
    results["suspicious_api_calls"] = analyze_suspicious_apis(apk_path)

    console.print("\n[bold cyan]Running Signature Analysis...[/bold cyan]")
    show_progress_bar("Signature Analysis")
    results["signature_analysis"] = analyze_signature(apk_path)

    return results

def main():
    show_banner()

    console.print("\n[bold yellow]CHOOSE YOUR INPUT METHOD:[/bold yellow]")
    console.print("(A) Connect your device")
    console.print("(B) Upload extracted APKs")

    input_choice = input("\nEnter your choice (A/B): ").strip().upper()

    apk_path = None

    if input_choice == "A":
        run_usb_device_operations()
        apk_path = "extracted_apks/sample.apk"
    elif input_choice == "B":
        apk_path = upload_apk_via_dialog()
        if not apk_path:
            console.print("[red]No APK selected. Exiting.[/red]")
            sys.exit(1)
    else:
        console.print("[red]Invalid choice. Exiting.[/red]")
        sys.exit(1)

    analysis_results = run_all_analyses(apk_path)

    console.print("\n[bold yellow]Checking if the APK is malicious...[/bold yellow]")
    decision_result = decide_maliciousness(apk_path)

    console.print("\n[bold yellow]Final Verdict:[/bold yellow]")
    if decision_result["status"] == "MALICIOUS":
        console.print("⚠️  [bold red]Device Classified as MALICIOUS based on:[/bold red]")
        for reason in decision_result["reasons"]:
            console.print(f"  - {reason}")
    else:
        console.print("✅ [bold green]Device Classified as SAFE — No major issues detected.[/bold green]")

    final_report_data = {
        "analysis_result": analysis_results,
        "maliciousness_decision": decision_result
    }

    console.print("\n[bold cyan]Generating reports in all formats (PDF, JSON, HTML)...[/bold cyan]")
    report_status = generate_reports(final_report_data, "reports")

    success_formats = [fmt.upper() for fmt, success in report_status.items() if success]
    failed_formats = [fmt.upper() for fmt, success in report_status.items() if not success]

    if failed_formats:
        console.print(f"\n[bold yellow]Reports generated partially:[/bold yellow] {', '.join(success_formats)}")
        console.print(f"[bold red]Failed to generate:[/bold red] {', '.join(failed_formats)}")
    else:
        console.print("\n[bold green]REPORTS GENERATED IN ALL FORMATS.[/bold green]")

    console.print("\n[bold magenta]THANK YOU FOR CHOOSING FORENSIPIE![/bold magenta]")

if __name__ == "__main__":
    main()
