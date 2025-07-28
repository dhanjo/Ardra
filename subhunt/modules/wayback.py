import subprocess
import os

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running command: {command}\n{result.stderr}")
    return result.stdout

def wayback(domain):
    print(f"[*] Running WayBackMachine for {domain}...")
    command = f"curl -sk 'http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=txt&fl=original&collapse=urlkey&page=' | awk -F/ '{{gsub(/:.*/, \"\", $3); print $3}}' | sort -u"
    
    raw_output = run_command(command)
    subdomains = []
    if raw_output:
        subdomains = [line.strip() for line in raw_output.splitlines() if line.strip()]
    
    # Append to subenum-{domain}.txt
    if subdomains:
        with open(f"subenum-{domain}.txt", "a") as f:
            for sub in subdomains:
                f.write(sub + "\n")
    print(f"[*] WayBackMachine found {len(subdomains)} subdomains for {domain}.")
    # No return
