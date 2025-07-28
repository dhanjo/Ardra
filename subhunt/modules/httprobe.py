import subprocess
import os
from datetime import datetime

def run_command_pipe(command_parts):
    # This function is for piping commands, so it takes a list of command parts
    # Example: [["sort", "input.txt"], ["httprobe"]]
    processes = []
    last_process = None
    for i, cmd_part in enumerate(command_parts):
        if i == 0:
            # First command in the pipe
            p = subprocess.Popen(cmd_part, stdout=subprocess.PIPE, text=True)
        else:
            # Subsequent commands, pipe stdout from previous process
            p = subprocess.Popen(cmd_part, stdin=last_process.stdout, stdout=subprocess.PIPE, text=True)
            if last_process.stdout: # Ensure the previous stdout pipe is closed for proper cleanup
                last_process.stdout.close()
        processes.append(p)
        last_process = p

    # Wait for all processes to complete and get the final output
    stdout, stderr = last_process.communicate()

    for p in processes:
        p.wait()

    if last_process.returncode != 0:
        print(f"Error in piped command: {stderr}")
        return ""
    return stdout

def run_httprobe(subdomains_list, domain):
    print(f"[*] Running HTTProbe for {domain}...")
    
    # Write the subdomains list to a temporary file for httprobe input
    input_file = f"tmp-httprobe-input-{domain}.txt"
    with open(input_file, "w") as f:
        for sub in subdomains_list:
            f.write(sub + "\n")

    # Command to run httprobe and get output
    command = ["httprobe"]
    raw_output = run_command_pipe([["cat", input_file], command])
    
    os.remove(input_file) # Clean up the temporary input file

    live_subdomains = []
    if raw_output:
        live_subdomains = [line.strip() for line in raw_output.splitlines() if line.strip()]

    print(f"[*] HTTProbe found {len(live_subdomains)} live subdomains for {domain}.")
    return live_subdomains
