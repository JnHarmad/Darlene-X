import pyfiglet
from rich.console import Console

# Initialize console for Rich library
console = Console()

def show_banner():
    """Display a styled banner for 'DARLENE-X'."""
    ascii_art = pyfiglet.figlet_format("DARLENE-X", font="slant", justify="center")
    styled_ascii_art = ""
    for i, line in enumerate(ascii_art.splitlines()):
        if i % 2 == 0:
            styled_ascii_art += f"[bold bright_blue]{line.center(100)}[/bold bright_blue]\n"
        else:
            styled_ascii_art += f"[bold magenta]{line.center(100)}[/bold magenta]\n"
    welcome_message = "[bold green]Welcome To...[/bold green]\n"
    tool_name = "[bold cyan]Darlene-X - Android Static Analysis Tool[/bold cyan]\n"
    version_number = "[bold yellow]Version: 1.0.0[/bold yellow]"
    analyzer_label = "[bold white]Android Static Analyzer[/bold white]"
    full_content = (
        styled_ascii_art.strip() + "\n" +
        welcome_message + tool_name + version_number + "\n" +
        analyzer_label
    )
    console.print(full_content)

if __name__ == "__main__":
    show_banner()
