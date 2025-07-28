from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
import time

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
    if not domain or len(domain) == 0 or len(domain) > 253:
        return False
    
    # Check for path traversal attempts
    if "../" in domain or ".." in domain:
        return False
    
    # Check for script tags and other suspicious content
    if "<" in domain or ">" in domain or "script" in domain.lower():
        return False
    
    # Basic domain regex - must have at least one dot and valid characters
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    return bool(domain_pattern.match(domain))

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

    # Simulate processing time
    time.sleep(1)
    
    # Return mock result
    return jsonify({
        "status": "success",
        "message": f"Successfully processed subdomains for {domain}",
        "subdomains": ["www." + domain, "api." + domain],
        "total_found": 2,
        "returned": 2
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001)