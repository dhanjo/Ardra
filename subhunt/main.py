import psycopg2
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import os
import re
import gc
import resource

# Set memory limit to 1GB to prevent memory exhaustion
try:
    resource.setrlimit(resource.RLIMIT_AS, (1024*1024*1024, 1024*1024*1024))
except Exception as e:
    print(f"Warning: Could not set memory limit: {e}")

from modules.wayback import wayback
from modules.crt import crt
from modules.findomain import findomain
from modules.subfinder import subfinder
# from modules.assetfinder import assetfinder # Commented out assetfinder import
from modules.combine import combine_results # Removed combine_results import
from modules.httprobe import run_httprobe

app = Flask(__name__)

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["100 per hour", "10 per minute"],
    storage_uri="memory://"
)

def validate_domain(domain):
    """Validate domain format and prevent malicious input"""
    if not domain or len(domain) > 253:
        return False
    
    # Basic domain regex
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    return bool(domain_pattern.match(domain))

def get_db_connection():
    conn = psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT", 5432),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD")
    )
    return conn

# Function to handle subdomain enumeration logic
def enumerate_subdomains(domain):
    try:
        # Remove any existing subenum file to avoid appending to old data
        subenum_file = f"subenum-{domain}.txt"
        if os.path.exists(subenum_file):
            os.remove(subenum_file)

        # Run all enumeration modules (side effect: append to subenum-{domain}.txt)
        wayback(domain)
        crt(domain)
        findomain(domain)
        subfinder(domain)
        # assetfinder(domain) # Uncomment if you want to use assetfinder

        # Deduplicate subenum file using streaming to handle large files
        unique_subdomains = []
        if os.path.exists(subenum_file):
            seen = set()
            with open(subenum_file, "r") as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain and subdomain not in seen:
                        seen.add(subdomain)
                        unique_subdomains.append(subdomain)
            
            # Sort and rewrite file
            unique_subdomains.sort()
            with open(subenum_file, "w") as f:
                for sub in unique_subdomains:
                    f.write(sub + "\n")

        # Run httprobe and write to httprobe-{domain}.txt
        # live_subdomains = []
        # if unique_subdomains:
        #     live_subdomains = run_httprobe(unique_subdomains, domain)
        #     httprobe_file = f"httprobe-{domain}.txt"
        #     with open(httprobe_file, "w") as f:
        #         for sub in live_subdomains:
        #             f.write(sub + "\n")

        # Insert discovered subdomains into the database in batches to handle large datasets
        if unique_subdomains:
            conn = None
            try:
                conn = get_db_connection()
                cur = conn.cursor()
                insert_query = "INSERT INTO subdomains (domain_name, subdomain, discovered_at) VALUES (%s, %s, %s) ON CONFLICT (domain_name, subdomain) DO NOTHING"
                current_time = datetime.now()
                
                # Process in batches to avoid memory issues
                batch_size = 1000
                for i in range(0, len(unique_subdomains), batch_size):
                    batch = unique_subdomains[i:i+batch_size]
                    try:
                        batch_data = [(domain, subdomain, current_time) for subdomain in batch]
                        cur.executemany(insert_query, batch_data)
                        conn.commit()
                        print(f"Inserted batch {i//batch_size + 1}: {len(batch)} subdomains")
                    except Exception as batch_e:
                        print(f"[DB ERROR] Failed to insert batch {i//batch_size + 1}: {batch_e}")
                        conn.rollback()
                        # Try individual inserts for failed batch
                        for subdomain in batch:
                            try:
                                cur.execute(insert_query, (domain, subdomain, current_time))
                                conn.commit()
                            except Exception as sub_e:
                                print(f"[DB ERROR] Failed to insert subdomain '{subdomain}': {sub_e}")
                                conn.rollback()
                
                cur.close()
                print(f"Successfully processed {len(unique_subdomains)} subdomains for {domain} in the database.")
            except Exception as db_e:
                print(f"[DB ERROR] Database insertion failed: {db_e}")
                if conn:
                    conn.rollback()
            finally:
                if conn:
                    conn.close()

        # Remove all tmp-* files
        for fname in os.listdir('.'):
            if fname.startswith('tmp-'):
                try:
                    os.remove(fname)
                except Exception as e:
                    print(f"Could not remove {fname}: {e}")

        # Read discovered subdomains for response (limit to prevent memory issues)
        discovered_subdomains = []
        if os.path.exists(subenum_file):
            max_subdomains = 10000  # Limit response size
            count = 0
            with open(subenum_file, "r") as f:
                for line in f:
                    if count >= max_subdomains:
                        break
                    subdomain = line.strip()
                    if subdomain:
                        discovered_subdomains.append(subdomain)
                        count += 1

        # Force garbage collection to free memory
        gc.collect()

        return {
            "status": "success",
            "message": f"Successfully processed subdomains for {domain}",
            "subdomains": discovered_subdomains,
            "total_found": len(unique_subdomains),
            "returned": len(discovered_subdomains)
        }

    except Exception as e:
        print(f"Error in enumeration: {e}")
        return {"status": "error", "message": str(e)}

# API endpoint for subdomain enumeration
@app.route("/api/enumerate", methods=["POST"])
@limiter.limit("5 per minute")  # More restrictive rate limit for this endpoint
def api_enumerate():
    data = request.json
    if not data or "domain" not in data:
        return jsonify({"status": "error", "message": "Domain is required"}), 400

    domain = data["domain"].strip().lower()
    
    # Validate domain format
    if not validate_domain(domain):
        return jsonify({"status": "error", "message": "Invalid domain format"}), 400

    # Run the enumeration process
    result = enumerate_subdomains(domain)
    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001)
