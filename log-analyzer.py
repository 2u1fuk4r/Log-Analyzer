import re
import subprocess
import argparse
from collections import Counter, defaultdict
from rich.console import Console
from rich.table import Table

console = Console()

def print_banner():
    banner = """
╔════════════════════════════════════╗
║           LOG ANALYZER             ║
║   FINAL INTERNATIONAL UNIVERSITY   ║
║          made by 2u1fuk4r          ║
╚════════════════════════════════════╝
"""
    console.print(banner, style="bold cyan")

def get_journal_logs():
    result = subprocess.run(
        ['journalctl', '-u', 'ssh.service', '--since', '1 hour ago', '--no-pager', '--output=short'],
        stdout=subprocess.PIPE, text=True
    )
    return result.stdout.splitlines()

def parse_logs(lines):
    failed_logins = Counter()
    suspicious_logins = defaultdict(list)
    system_errors = []

    ip_regex = re.compile(
        r"from ((?:\d{1,3}\.){3}\d{1,3}|(?:[a-fA-F0-9:]+))"
    )

    for line in lines:
        lower = line.lower()
        if "failed password" in lower:
            ip_match = ip_regex.search(line)
            if ip_match:
                ip = ip_match.group(1)
                failed_logins[ip] += 1
        elif "accepted password" in lower:
            user_match = re.search(r"for (\w+)", line)
            ip_match = ip_regex.search(line)
            if user_match and ip_match:
                user = user_match.group(1)
                ip = ip_match.group(1)
                suspicious_logins[user].append(ip)
        elif "error" in lower or "kernel:" in lower:
            system_errors.append(line.strip())

    return failed_logins, suspicious_logins, system_errors

def generate_report(failed_logins, suspicious_logins, system_errors):
    console.rule("[bold green]Security Summary Report")

    table1 = Table(title="Failed SSH Login Attempts")
    table1.add_column("IP Address", style="red")
    table1.add_column("Attempt Count", style="yellow")

    for ip, count in failed_logins.items():
        if count >= 1:
            table1.add_row(ip, str(count))

    if table1.row_count:
        console.print(table1)
    else:
        console.print("[green]No suspicious failed logins found.")

    table2 = Table(title="Accepted SSH Logins (Multiple IPs)")
    table2.add_column("Username", style="cyan")
    table2.add_column("IP Addresses", style="magenta")

    for user, ips in suspicious_logins.items():
        if len(set(ips)) > 1:
            table2.add_row(user, ", ".join(set(ips)))

    if table2.row_count:
        console.print(table2)
    else:
        console.print("[green]No unusual user login activity detected.")

    if system_errors:
        console.print("\n[bold red]System Errors or Kernel Warnings:")
        for err in system_errors[:5]:
            console.print(f"[yellow]- {err}")
    else:
        console.print("[green]No critical system errors or warnings found.")

def clear_journal_logs():
    console.print("[bold red]⚠ you will remove permanently for ssh and systemc logs ![/bold red]")
    confirm = input("Are you sure ? [y/N]: ")
    if confirm.lower() != 'y':
        console.print("[yellow]process canceled.[/yellow]")
        return

    console.print("[red]➤ Rotating journal...[/red]")
    subprocess.run(['journalctl', '--rotate'], stdout=subprocess.DEVNULL)

    console.print("[red]➤ Vacuuming old logs...[/red]")
    subprocess.run(['journalctl', '--vacuum-time=1s'], stdout=subprocess.DEVNULL)

    console.print("[green]✅ systemd journal logs cleared.[/green]")

def main():
    parser = argparse.ArgumentParser(description="Log Analyzer Tool")
    parser.add_argument('-r', '--reset', action='store_true', help='Delete systemd SSH logs permanently')
    args = parser.parse_args()

    print_banner()

    if args.reset:
        clear_journal_logs()
        return

    lines = get_journal_logs()
    failed_logins, suspicious_logins, system_errors = parse_logs(lines)
    generate_report(failed_logins, suspicious_logins, system_errors)

    console.print("\n[bold cyan]Recommendations:")
    if any(failed_logins.values()):
        console.print("- [yellow]Consider blocking IPs with failed login attempts (e.g., fail2ban).")
    if any(len(set(ips)) > 1 for ips in suspicious_logins.values()):
        console.print("- [yellow]Review users logging in from multiple IP addresses.")
    if system_errors:
        console.print("- [yellow]Investigate system errors or kernel warnings.")
    if not (failed_logins or suspicious_logins or system_errors):
        console.print("- [green]System appears clean and secure.")

if __name__ == "__main__":
    main()
