import os
import sys
import time
import threading
from rich.console import Console
from progress.bar import Bar

from forensipie.modules.banner_display import show_banner
from forensipie.modules.usb_connection import run_usb_device_operations, upload_apk_via_dialog
from forensipie.modules.decide_malicious import gather_all_analysis, decide_maliciousness
from forensipie.modules.report_generator import generate_reports

console = Console()

class TaskProgressBar:
    def __init__(self, task_name, wait_time=5):
        self.task_name = task_name
        self.wait_time = wait_time
        self.progress = 0
        self.running = False
        self.completed = False
        self.bar = Bar(task_name, max=100)
        
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._run)
        self.thread.daemon = True
        self.thread.start()
        
    def _run(self):
        while self.running and self.progress < 100:
            if self.progress < 95:  # Leave room for completion
                increment = max(1, min(5, int(95 / (self.wait_time * 10))))
                self.progress += increment
                self.bar.goto(self.progress)
                time.sleep(0.1)
            else:
                time.sleep(0.05)
        
    def complete(self):
        self.running = False
        if self.thread.is_alive():
            self.thread.join(0.5)
        self.progress = 100
        self.bar.goto(100)
        self.bar.finish()
        self.completed = True

def run_all_analysis_with_progress(apk_path):
    results = {}
    tasks = [
        {"name": "APK Unpack and Decompile", "time": 3},
        {"name": "Manifest Analysis", "time": 2},
        {"name": "Database Encryption Analysis", "time": 2},
        {"name": "Suspicious API Analysis", "time": 2},
        {"name": "Signature Analysis", "time": 3}
    ]
    console.print("\n[bold cyan]Running All Analysis Modules...[/bold cyan]")
    
    # Verify the APK file exists
    if not os.path.exists(apk_path):
        console.print(f"[bold red]ERROR: APK file not found at {apk_path}[/bold red]")
        console.print("[yellow]Please check if the APK path is correct and try again.[/yellow]")
        return {
            'apk_unpack': {
                'Classes': 0,
                'Methods': 0,
                'status': 'Failed',
                'error': f'APK file not found: {apk_path}'
            },
            'manifest': {
                'package_name': 'Unknown',
                'permissions': []
            }
        }
    
    try:
        console.print(f"[green]Analyzing APK: {apk_path}[/green]")
        console.print(f"[green]File size: {os.path.getsize(apk_path) / (1024*1024):.2f} MB[/green]")
        
        # Create event to signal when analysis is complete
        analysis_complete = threading.Event()
        analysis_result = [None]  # Use a list to store the result from the thread
        
        # Start the actual analysis in a separate thread
        def run_analysis():
            try:
                result = gather_all_analysis(apk_path)
                analysis_result[0] = result
            except Exception as e:
                console.print(f"[bold red]Error during analysis: {str(e)}[/bold red]")
                import traceback
                console.print(f"[red]{traceback.format_exc()}[/red]")
            finally:
                analysis_complete.set()
                
        analysis_thread = threading.Thread(target=run_analysis)
        analysis_thread.daemon = True
        analysis_thread.start()
        
        # Show progress bars while analysis is running
        progress_bars = []
        total_progress_time = sum(task["time"] for task in tasks)
        time_so_far = 0
        
        for task in tasks:
            # Calculate how much of the total time this task represents
            task_percentage = task["time"] / total_progress_time
            
            # Create and show progress bar
            progress_bar = TaskProgressBar(task["name"], task["time"])
            progress_bars.append(progress_bar)
            progress_bar.start()
            
            # Wait for either the task's display time or until analysis completes
            for _ in range(task["time"] * 10):  # 10 increments per second
                if analysis_complete.is_set():
                    break
                time.sleep(0.1)
            
            progress_bar.complete()
            time_so_far += task["time"]
            
            # If analysis is already complete, speed up remaining progress bars
            if analysis_complete.is_set():
                remaining_tasks = tasks[tasks.index(task) + 1:]
                if remaining_tasks:
                    console.print("[cyan]Analysis completed, finishing display...[/cyan]")
                    for remaining_task in remaining_tasks:
                        fast_bar = TaskProgressBar(remaining_task["name"], 0.5)  # Show quickly
                        fast_bar.start()
                        time.sleep(0.5)
                        fast_bar.complete()
                break
        
        # Wait for analysis to complete if it's still running
        if not analysis_complete.is_set():
            console.print("[cyan]Finalizing analysis...[/cyan]")
            analysis_complete.wait()
        
        # Get the results from the completed analysis
        results = analysis_result[0]
        if results is None:
            # Something went wrong, create default structure
            console.print("[red]Analysis failed to return results. Creating default structure.[/red]")
            results = {
                'apk_unpack': {
                    'Classes': 0,
                    'Methods': 0,
                    'status': 'Failed',
                    'error': 'Analysis did not complete successfully'
                },
                'manifest': {
                    'package_name': 'Unknown',
                    'permissions': []
                }
            }
            
        # Ensure basic structure exists even on partial failures
        if 'apk_unpack' not in results:
            results['apk_unpack'] = {
                'Classes': 0,
                'Methods': 0
            }
        if 'manifest' not in results:
            results['manifest'] = {
                'package_name': 'Unknown',
                'permissions': []
            }
    
    except Exception as outer_e:
        console.print(f"[bold red]Critical error during analysis process: {str(outer_e)}[/bold red]")
        import traceback
        console.print(f"[red]{traceback.format_exc()}[/red]")
        results = {
            'apk_unpack': {
                'Classes': 0,
                'Methods': 0,
                'status': 'Failed',
                'error': f'Critical error: {str(outer_e)}'
            },
            'manifest': {
                'package_name': 'Unknown',
                'permissions': []
            }
        }
        
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
        # Check if the default path exists or prompt the user
        default_path = "extracted_apks/sample.apk"
        if os.path.exists(default_path):
            apk_path = default_path
        else:
            console.print("[yellow]Default APK path not found. Please select an APK file.[/yellow]")
            apk_path = upload_apk_via_dialog()
    elif input_choice == "B":
        apk_path = upload_apk_via_dialog()
        if not apk_path:
            console.print("[red]No APK selected. Exiting.[/red]")
            sys.exit(1)
    else:
        console.print("[red]Invalid choice. Exiting.[/red]")
        sys.exit(1)
    
    # Ensure APK path is absolute
    apk_path = os.path.abspath(apk_path)
    console.print(f"[green]Selected APK: {apk_path}[/green]")

    analysis_results = run_all_analysis_with_progress(apk_path)
    
    # Create a default structure if analysis failed completely
    if not analysis_results:
        console.print("[red]Analysis failed. Creating minimal structure to continue.[/red]")
        analysis_results = {
            'apk_unpack': {
                'Classes': 0,
                'Methods': 0,
                'status': 'Failed',
                'error': 'Analysis failed to complete'
            },
            'manifest': {
                'package_name': 'Unknown',
                'permissions': []
            }
        }

    console.print("\n[bold yellow]Checking if the APK is malicious...[/bold yellow]")
    try:
        decision_result = decide_maliciousness(apk_path, precomputed_results=analysis_results)
    except Exception as e:
        console.print(f"[red]Error during maliciousness decision: {e}[/red]")
        decision_result = {
            "status": "Error",
            "error": str(e),
            "reasons": ["Analysis encountered errors"]
        }

    console.print("\n[bold yellow]Final Verdict:[/bold yellow]")
    if decision_result["status"] == "MALICIOUS":
        console.print("\U000026A0\ufe0f  [bold red]Device Classified as MALICIOUS based on:[/bold red]")
        for reason in decision_result.get("reasons", []):
            console.print(f"  - {reason}")
    elif decision_result["status"] == "SAFE":
        console.print("\u2705 [bold green]Device Classified as SAFE — No major issues detected.[/bold green]")
    else:
        console.print(f"\u274C [bold red]Error in determining maliciousness: {decision_result.get('error', 'Unknown error')}[/bold red]")

    # Ensure we have a valid data structure for the report
    final_report_data = {
        "analysis_result": analysis_results,
        "maliciousness_decision": decision_result
    }

    # Explicitly ensure the APK unpack data has class and method counts
    if 'apk_unpack' not in analysis_results:
        analysis_results['apk_unpack'] = {}
    
    apk_unpack_info = analysis_results.get('apk_unpack', {})
    
    # Check for new structure and extract class/method info
    if 'statistics' in apk_unpack_info:
        class_count = apk_unpack_info.get('statistics', {}).get('total_classes', 0)
        method_count = apk_unpack_info.get('statistics', {}).get('total_methods', 0)
        # Update the old structure keys for compatibility
        apk_unpack_info['Classes'] = class_count
        apk_unpack_info['Methods'] = method_count
    else:
        # Use old structure keys
        class_count = apk_unpack_info.get('Classes', 0)
        method_count = apk_unpack_info.get('Methods', 0)
    
    # Debug output for verification - removing this entire section
    if class_count == 0 and method_count == 0:
        # Try to extract from available data
        if 'statistics' in apk_unpack_info:
            class_count = apk_unpack_info.get('statistics', {}).get('total_classes', 0)
            method_count = apk_unpack_info.get('statistics', {}).get('total_methods', 0)
            if class_count > 0 or method_count > 0:
                # Update the structure with found values
                analysis_results['apk_unpack']['Classes'] = class_count
                analysis_results['apk_unpack']['Methods'] = method_count
        
        # If no class/method data was found, we'll just continue with zeros
        # NO FALLBACKS with hardcoded values or "console-reported values as last resort"

    # Create reports directory if it doesn't exist
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)
    
    console.print("\n[bold cyan]Generating reports in all formats (PDF, JSON, HTML)...[/bold cyan]")
    report_status = generate_reports(final_report_data, reports_dir)

    success_formats = [fmt.upper() for fmt, success in report_status.items() if success]
    failed_formats = [fmt.upper() for fmt, success in report_status.items() if not success]

    if failed_formats:
        console.print(f"\n[bold yellow]Reports generated partially:[/bold yellow] {', '.join(success_formats)}")
        console.print(f"[bold red]Failed to generate:[/bold red] {', '.join(failed_formats)}")
    else:
        console.print("\n[bold green]REPORTS GENERATED IN ALL FORMATS.[/bold green]")
        console.print(f"[green]Reports saved to directory: {os.path.abspath(reports_dir)}[/green]")

    console.print("\n[bold magenta]THANK YOU FOR CHOOSING FORENSIPIE![/bold magenta]")

if __name__ == "__main__":
    main()
