import subprocess
import os

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running command: {command}\n{result.stderr}")
    return result.stdout

def assetfinder(domain):
    print(f"[*] Running AssetFinder for {domain}...")
    command = f"assetfinder --subs-only {domain}"
    
    raw_output = run_command(command)
    subdomains = []
    if raw_output:
        subdomains = [line.strip() for line in raw_output.splitlines() if line.strip()]
    
    print(f"[*] AssetFinder found {len(subdomains)} subdomains for {domain}.")
    return subdomains
