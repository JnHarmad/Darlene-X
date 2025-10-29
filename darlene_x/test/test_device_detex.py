# test_usb_connection.py
import os
from darlene_x.modules.usb_connection import USBConnection
from rich.console import Console

console = Console()

def test_wait_for_device():
    usb_conn = USBConnection()
    device_found = usb_conn.wait_for_device(timeout=10)
    if device_found:
        console.print("[bold cyan]Test Passed:[/bold cyan] Device detected successfully.")
    else:
        console.print("[bold red]Test Failed:[/bold red] No device detected.")

def test_restart_adb():
    usb_conn = USBConnection()
    usb_conn.restart_adb_server()
    console.print("[bold green]ADB server restart tested.[/bold green]")

def test_get_connected_device_info():
    usb_conn = USBConnection()
    if usb_conn.check_usb_connection():
        device_ids = os.popen("adb devices").read().strip().split("\n")[1:]
        if device_ids:
            device_id = device_ids[0].split("\t")[0]
            info = usb_conn.get_device_info(device_id)
            console.print(f"[bold green]Device Info:[/bold green] {info}")
        else:
            console.print("[bold yellow]No device info found.[/bold yellow]")
    else:
        console.print("[bold yellow]No connected device to fetch info from.[/bold yellow]")

if __name__ == "__main__":
    test_wait_for_device()
    test_restart_adb()
    test_get_connected_device_info()
