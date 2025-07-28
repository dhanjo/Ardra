import subprocess
import os

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running command: {command}\n{result.stderr}")
    return result.stdout

def crt(domain):
    print(f"[*] Running crt.sh for {domain}...")

    # Define the complex AWK script part as a separate string
    # The inner curly braces {} for AWK actions need to be escaped for the f-string that contains them
    awk_script_actions = '{{gsub(/\\*\\./, \"\", $4); gsub(/\\n/, \"\n\", $4); print $4}}'

    command = (
        f"curl -sk 'https://crt.sh/?q=%25.{domain}&output=json' | "
        f"tr ',' '\\n' | " # Escape newline for tr
        f"awk -F'\\\"' '/name_value/ {awk_script_actions}' | sort -u"
    )

    raw_output = run_command(command)
    subdomains = []
    if raw_output:
        subdomains = [line.strip() for line in raw_output.splitlines() if line.strip()]
    
    print(f"[*] crt.sh found {len(subdomains)} subdomains for {domain}.")
    return subdomains
