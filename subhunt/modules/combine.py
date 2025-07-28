import os
from datetime import datetime

def combine_results(domain):
    current_date = datetime.now().strftime("%Y-%m-%d")
    combined_file = f'subenum-{domain}-{current_date}.txt'
    unique_subdomains = set()

    for fname in [
        f'tmp-wayback-{domain}',
        f'tmp-crt-{domain}',
        f'tmp-findomain-{domain}',
        f'tmp-subfinder-{domain}',
        f'tmp-httprobe-input-{domain}.txt'
    ]:
        if os.path.exists(fname):
            with open(fname) as infile:
                for line in infile:
                    unique_subdomains.add(line.strip())
            os.remove(fname)

    with open(combined_file, 'w') as outfile:
        for subdomain in sorted(unique_subdomains):
            outfile.write(subdomain + "\n")
    
    print(f"Combined output saved to {combined_file}")
    return combined_file
