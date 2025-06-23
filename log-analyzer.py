import re
import subprocess
import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()
STORAGE_FILE = "log_analysis_history.json"

def print_banner():
    banner = """
╔════════════════════════════════════╗
║           LOG ANALYZER             ║
║                                    ║
║          made by 2u1fuk4r          ║
╚════════════════════════════════════╝
"""
    console.print(banner, style="bold cyan")

def build_journalctl_command(since, until):
    cmd = ['journalctl', '-u', 'ssh.service', '--no-pager', '--output=short']
    if since:
        cmd += ['--since', since]
    else:
        cmd += ['--since', '1 hour ago']
    if until:
        cmd += ['--until', until]
    return cmd

def get_journal_logs(since=None, until=None):
    cmd = build_journalctl_command(since, until)
    result = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)
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
            table2.add_row(user, ", ".join(sorted(set(ips))))

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
    console.print("[bold red]⚠ SSH and all systemd logs will be permanently deleted![/bold red]")
    confirm = input("Are you sure? This action cannot be undone. [y/N]: ")
    if confirm.lower() != 'y':
        console.print("[yellow]Operation cancelled.[/yellow]")
        return

    console.print("[red]➤ Rotating journal...[/red]")
    subprocess.run(['journalctl', '--rotate'], stdout=subprocess.DEVNULL)
    console.print("[red]➤ Vacuuming old logs...[/red]")
    subprocess.run(['journalctl', '--vacuum-time=1s'], stdout=subprocess.DEVNULL)
    console.print("[green]✅ systemd journal logs cleared.[/green]")

def save_history(failed_logins, suspicious_logins):
    # Load existing history
    try:
        with open(STORAGE_FILE, 'r') as f:
            history = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        history = {}

    # Update history with current counts
    for ip, count in failed_logins.items():
        history.setdefault('failed_logins', {})
        history['failed_logins'][ip] = history['failed_logins'].get(ip, 0) + count

    for user, ips in suspicious_logins.items():
        history.setdefault('suspicious_logins', {})
        old_ips = set(history['suspicious_logins'].get(user, []))
        new_ips = old_ips.union(set(ips))
        history['suspicious_logins'][user] = list(new_ips)

    with open(STORAGE_FILE, 'w') as f:
        json.dump(history, f, indent=2)

def load_history():
    try:
        with open(STORAGE_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def show_recommendations(failed_logins, suspicious_logins, system_errors):
    console.print("\n[bold cyan]Recommendations:")
    if any(failed_logins.values()):
        console.print("- [yellow]Consider blocking IPs with failed login attempts (e.g., fail2ban).")
    if any(len(set(ips)) > 1 for ips in suspicious_logins.values()):
        console.print("- [yellow]Review users logging in from multiple IP addresses.")
    if system_errors:
        console.print("- [yellow]Investigate system errors or kernel warnings.")
    if not (failed_logins or suspicious_logins or system_errors):
        console.print("- [green]System appears clean and secure.")

def print_blocking_commands(failed_logins):
    if not failed_logins:
        console.print("[green]No failed login IPs to recommend blocking.[/green]")
        return

    console.print("\n[bold magenta]IP Blocking Recommendations:")
    for ip, count in failed_logins.items():
        if count > 0:
            console.print(f"\n[bold]IP: {ip} — {count} failed attempts")
            console.print(f"iptables: sudo iptables -A INPUT -s {ip} -j DROP")
            console.print(f"fail2ban: Add to jail.local or use fail2ban-client to ban {ip}")

def export_report(failed_logins, suspicious_logins, system_errors, filename):
    report = {
        "failed_logins": dict(failed_logins),
        "suspicious_logins": {u: list(set(ips)) for u, ips in suspicious_logins.items()},
        "system_errors": system_errors[:10]
    }
    try:
        if filename.lower().endswith('.json'):
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            console.print(f"[green]Report exported as JSON to {filename}[/green]")
        elif filename.lower().endswith('.txt'):
            with open(filename, 'w') as f:
                f.write("=== Failed SSH Login Attempts ===\n")
                for ip, count in failed_logins.items():
                    f.write(f"{ip}: {count}\n")
                f.write("\n=== Accepted SSH Logins (Multiple IPs) ===\n")
                for user, ips in suspicious_logins.items():
                    if len(set(ips)) > 1:
                        f.write(f"{user}: {', '.join(set(ips))}\n")
                f.write("\n=== System Errors or Kernel Warnings ===\n")
                for err in system_errors[:10]:
                    f.write(f"{err}\n")
            console.print(f"[green]Report exported as TXT to {filename}[/green]")
        else:
            console.print("[red]Unsupported export file format. Use .json or .txt[/red]")
    except Exception as e:
        console.print(f"[red]Failed to export report: {e}[/red]")

def main():
    parser = argparse.ArgumentParser(
        description="SSH Log Analyzer Tool\n"
                    "Analyze SSH logs from systemd journal, detect suspicious activity, "
                    "and optionally reset logs or export reports."
    )
    parser.add_argument(
        '-r', '--reset',
        action='store_true',
        help='Permanently delete all systemd journal logs (requires root)'
    )
    parser.add_argument(
        '--since',
        type=str,
        default=None,
        help='Start time for logs (e.g., "2025-06-22 08:00:00" or "2 hours ago")'
    )
    parser.add_argument(
        '--until',
        type=str,
        default=None,
        help='End time for logs (e.g., "2025-06-22 10:00:00")'
    )
    parser.add_argument(
        '--export',
        type=str,
        metavar='FILE',
        default=None,
        help='Export the report to specified file (TXT or JSON based on extension)'
    )
    parser.add_argument(
        '--recommend',
        action='store_true',
        help='Show iptables/fail2ban commands to block IPs with failed logins'
    )
    args = parser.parse_args()

    print_banner()

    if args.reset:
        clear_journal_logs()
        return

    lines = get_journal_logs(args.since, args.until)
    failed_logins, suspicious_logins, system_errors = parse_logs(lines)
    generate_report(failed_logins, suspicious_logins, system_errors)

    if args.recommend:
        print_blocking_commands(failed_logins)

    if args.export:
        export_report(failed_logins, suspicious_logins, system_errors, args.export)

    save_history(failed_logins, suspicious_logins)
    show_recommendations(failed_logins, suspicious_logins, system_errors)


if __name__ == "__main__":
    main()
