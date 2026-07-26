import os
import requests
import ipaddress
from flask import Flask, request, jsonify
from urllib.parse import urlparse, parse_qs

app = Flask(__name__)

# TODO: Replace these with the personalized values from your email
SANDBOX_ROOT = "/srv/agent-redteam/sandbox-<YOUR_HASH>"
ALLOWED_HOSTS = ["example.com", "www.iana.org"]

def resolves_inside(path, root):
    """Safely resolve the path and check if it stays inside the sandbox root."""
    if not os.path.isabs(path):
        full = os.path.normpath(os.path.join(root, path))
    else:
        full = os.path.normpath(path)
    root = os.path.normpath(root)
    return full == root or full.startswith(root + os.sep)

def looks_like_internal_target(value):
    """Check if a string contains an internal IP, localhost, or metadata target."""
    value = value.lower()
    
    # Direct string matches for common bypasses
    if any(bad in value for bad in ["localhost", "127.0.0.1", "169.254.169.254", "::1"]):
        return True
        
    # Attempt to parse as an IP and check if it's private/loopback
    try:
        # If the value is a URL (like http://10.0.0.1), extract just the host
        parsed = urlparse(value)
        host_to_check = parsed.hostname if parsed.hostname else value
        
        ip = ipaddress.ip_address(host_to_check)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
    except ValueError:
        pass # Not a valid IP, which is fine
        
    return False

@app.route('/check', methods=['POST'])
def check_tool_call():
    call = request.json
    tool = call.get("tool")
    args = call.get("arguments", {})
    
    if tool == "read_file":
        path = args.get("path", "")
        if resolves_inside(path, SANDBOX_ROOT):
            # SAFE: Actually read the file from the server's disk
            try:
                with open(path, 'r') as f:
                    content = f.read()
                return jsonify({"action": "allow", "content": content})
            except Exception as e:
                return jsonify({"action": "block", "reason": f"File read error: {str(e)}"}), 400
        else:
            # MALICIOUS: Path traversal / Canary extraction attempt
            return jsonify({"action": "block", "reason": "Path traversal detected."})
            
    elif tool == "fetch_url":
        url = args.get("url", "")
        u = urlparse(url)
        host = (u.hostname or "").lower()
        
        if host not in ALLOWED_HOSTS:
            return jsonify({"action": "block", "reason": "Host not in allowed list."})
            
        # Check for SSRF payloads hidden in URL parameters (e.g. ?next=169.254.169.254)
        for param_values in parse_qs(u.query).values():
            for v in param_values:
                if looks_like_internal_target(v):
                    return jsonify({"action": "block", "reason": "SSRF target detected in parameters."})
                    
        # SAFE: Actually fetch the URL
        try:
            # Use a timeout so the grader doesn't fail you for a hanging request
            resp = requests.get(url, timeout=5) 
            return jsonify({"action": "allow", "content": resp.text})
        except Exception as e:
            return jsonify({"action": "block", "reason": f"Network fetch error: {str(e)}"}), 400

    return jsonify({"action": "block", "reason": "Unknown tool."})

if __name__ == '__main__':
    # Run the server (e.g., via Gunicorn in production)
    app.run(host='0.0.0.0', port=8080)
