import subprocess
import time
import os
import concurrent.futures
from rich.console import Console
from rich.progress import SpinnerColumn, TextColumn, Progress
from tkinter import Tk, filedialog

console = Console()

def show_waiting_message(message: str, timeout: int):
    """Display a spinner with a waiting message for USB connection."""
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console
    ) as progress:
        task = progress.add_task(description=message, total=None)
        time.sleep(timeout)  # purely visual effect

class USBConnection:
    def __init__(self, adb_path="adb"):
        self.adb_path = "E:/platform-tools/adb.exe"

    def check_usb_connection(self) -> bool:
        result = subprocess.run([self.adb_path, "devices"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "\tdevice" in line:
                return True
        return False

    def wait_for_device(self, timeout: int = 30) -> bool:
        console.print("[bold green]Waiting for device to be connected via USB...[/bold green]")
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.check_usb_connection():
                console.print("[bold cyan]Device detected via USB.[/bold cyan]")
                return True
            time.sleep(1)
        console.print("[bold red]No device detected within the timeout period.[/bold red]")
        return False

    def restart_adb_server(self) -> None:
        subprocess.run([self.adb_path, "kill-server"], capture_output=True, text=True)
        subprocess.run([self.adb_path, "start-server"], capture_output=True, text=True)
        console.print("[yellow]ADB server restarted.[/yellow]")

    def get_device_info(self, device_id: str) -> dict:
        info = {}
        commands = {
            "model": ["-s", device_id, "shell", "getprop", "ro.product.model"],
            "manufacturer": ["-s", device_id, "shell", "getprop", "ro.product.manufacturer"],
            "android_version": ["-s", device_id, "shell", "getprop", "ro.build.version.release"],
        }
        for key, command in commands.items():
            result = subprocess.run([self.adb_path] + command, capture_output=True, text=True)
            info[key] = result.stdout.strip()
        return info

class AndroidDeviceManager:
    def __init__(self, adb_path="adb"):
        self.adb_path = adb_path

    def detect_devices(self) -> list:
        result = subprocess.run([self.adb_path, "devices"], capture_output=True, text=True)
        devices = []
        for line in result.stdout.splitlines():
            if "\tdevice" in line:
                device_id = line.split("\t")[0]
                devices.append(device_id)
        return devices

    def list_installed_apks(self, device_id: str) -> list:
        command = [self.adb_path, "-s", device_id, "shell", "pm", "list", "packages", "-f"]
        result = subprocess.run(command, capture_output=True, text=True)
        apks = []
        for line in result.stdout.splitlines():
            if "package:" in line:
                apk_path = line.split("package:")[1].split("=")[0]
                package_name = line.split("=")[1]
                apks.append((package_name, apk_path))
        return apks

    def extract_apk(self, device_id: str, apk_path: str, output_dir: str) -> None:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        output_file = os.path.join(output_dir, os.path.basename(apk_path))
        command = [self.adb_path, "-s", device_id, "pull", apk_path, output_file]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            console.print(f"[green]APK extracted successfully: {output_file}[/green]")
        else:
            console.print(f"[red]Failed to extract APK: {result.stderr}[/red]")

    
        def extract_all_apks(self, device_id: str, output_dir: str) -> list[tuple[str, str]]:
         """Fetch and pull base.apk of each app instead of broken split APK paths."""
        command = [self.adb_path, "-s", device_id, "shell", "pm", "list", "packages"]
        result = subprocess.run(command, capture_output=True, text=True)
        package_names = [line.replace("package:", "").strip() for line in result.stdout.splitlines() if "package:" in line]

        pulled_apks = []

        for package in package_names:
            # Get the actual path to base.apk
            path_cmd = [self.adb_path, "-s", device_id, "shell", "pm", "path", package]
            path_result = subprocess.run(path_cmd, capture_output=True, text=True)
            if "package:" in path_result.stdout:
                remote_apk_path = path_result.stdout.strip().split("package:")[1]
                local_filename = f"{package}.apk"
                local_path = os.path.join(output_dir, local_filename)

                pull_cmd = [self.adb_path, "-s", device_id, "pull", remote_apk_path, local_path]
                pull_result = subprocess.run(pull_cmd, capture_output=True, text=True)
                if pull_result.returncode == 0:
                    console.print(f"[green]Extracted APK: {local_filename}[/green]")
                    pulled_apks.append((package, local_path))
                else:
                    console.print(f"[red]Failed to pull {package}: {pull_result.stderr}[/red]")

        return pulled_apks

    def process_apks_in_batch(self, apks: list, output_dir: str, batch_size: int = 5):
        """Batch process APKs for analysis."""
        batches = [apks[i:i + batch_size] for i in range(0, len(apks), batch_size)]
        return batches

    def analyze_apk(self, apk_path: str, output_dir: str):
        """Function to analyze a single APK (example placeholder)."""
        console.print(f"[cyan]Analyzing APK: {apk_path}[/cyan]")
        time.sleep(1)

    def parallel_process_apks(self, apks: list, output_dir: str, max_workers: int = 4):
        """Parallel processing of APKs."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for apk_path, _ in apks:
                futures.append(executor.submit(self.analyze_apk, apk_path, output_dir))
            for future in concurrent.futures.as_completed(futures):
                future.result()

    def process_and_analyze_apks(self, device_id: str, output_dir: str):
        """Extract, batch process, and analyze APKs."""
        apks = self.extract_all_apks(device_id, output_dir)
        batches = self.process_apks_in_batch(apks, output_dir, batch_size=5)
        for batch in batches:
            self.parallel_process_apks(batch, output_dir)

# === New logic added carefully === #

def upload_apk_via_dialog() -> str:
    """Opens a Tkinter file dialog to upload APK files."""
    root = Tk()
    root.withdraw()  # Hide the main Tk window
    apk_path = filedialog.askopenfilename(
        title="Select an APK file",
        filetypes=[("APK files", "*.apk")]
    )
    if apk_path:
        console.print(f"[green]APK Selected: {apk_path}[/green]")
    else:
        console.print("[red]No APK selected.[/red]")
    return apk_path

def run_usb_device_operations():
    usb_connection = USBConnection()
    device_manager = AndroidDeviceManager(adb_path=usb_connection.adb_path)

    if usb_connection.wait_for_device(timeout=30):
        devices = device_manager.detect_devices()
        if devices:
            device_id = devices[0]
            console.print(f"[bold cyan]Using device:[/bold cyan] {device_id}")

            device_info = usb_connection.get_device_info(device_id)
            console.print(f"[bold magenta]Device Info:[/bold magenta] {device_info}")

            output_dir = "extracted_apks"
            console.print("[bold yellow]Extracting APKs...[/bold yellow]")
            device_manager.process_and_analyze_apks(device_id, output_dir)
            console.print("[bold green]COMPLETED SUCCESSFULLY![/bold green]")
        else:
            console.print("[red]No devices found. Exiting.[/red]")
    else:
        console.print("[red]No device detected. Exiting.[/red]")

def main_menu():
    """Main menu to choose between USB connection or file upload."""
    console.print("\n[bold yellow]CHOOSE YOUR INPUT METHOD:[/bold yellow]")
    console.print("(A) Connect your device")
    console.print("(B) Upload extracted APKs")

    choice = input("\nEnter your choice (A/B): ").strip().upper()

    if choice == "A":
        run_usb_device_operations()
    elif choice == "B":
        apk_path = upload_apk_via_dialog()
        if apk_path:
            # You can call your static analysis function here if needed
            console.print(f"[bold green]Ready to analyze uploaded APK: {apk_path}[/bold green]")
        else:
            console.print("[red]No APK selected. Exiting.[/red]")
    else:
        console.print("[red]Invalid choice. Please select A or B.[/red]")

if __name__ == "__main__":
    main_menu()
