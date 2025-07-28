import subprocess
import os

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    print(f"DEBUG: Command: {command}")
    print(f"DEBUG: Stdout:\n{result.stdout}")
    if result.stderr:
        print(f"DEBUG: Stderr:\n{result.stderr}")
    if result.returncode != 0:
        print(f"Error running command (exit code {result.returncode}): {command}")
    return result.stdout

def findomain(domain):
    output_file = f"tmp-findomain-{domain}.txt"
    
    # Construct the command without any API keys
    command = f"findomain -t {domain} -u {output_file}"
    
    print(f"[*] Running Findomain for {domain}...")
    run_command(command)
    
    subdomains = []
    if os.path.exists(output_file):
        with open(output_file, "r") as f:
            subdomains = [line.strip() for line in f if line.strip()]
        os.remove(output_file) # Clean up the temporary file
    
    # Append to subenum-{domain}.txt
    if subdomains:
        with open(f"subenum-{domain}.txt", "a") as f:
            for sub in subdomains:
                f.write(sub + "\n")
    
    print(f"[*] Findomain found {len(subdomains)} subdomains for {domain}.")
    # No return
