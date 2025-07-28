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

def subfinder(domain):
    output_file = f"tmp-subfinder-{domain}.txt"
    
    command_parts = [f"subfinder -all -silent -d {domain}"]

    # Subfinder typically uses a config file for API keys. 
    # For this Docker setup, consider mounting a config file or handling it otherwise.
    # Example: -config /path/to/subfinder_config.yaml

    command_parts.append(f"> {output_file}")
    command = " ".join(command_parts)
    
    print(f"[*] Running Subfinder for {domain}...")
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
    print(f"[*] Subfinder found {len(subdomains)} subdomains for {domain}.")
    # No return
