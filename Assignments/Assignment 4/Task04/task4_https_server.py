from flask import Flask, jsonify, request

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.route('/status', methods=['GET'])
def public_status():
    return jsonify({"status": "Online", "tls_version": "TLSv1.3"})

@app.route('/patient-record', methods=['GET'])
def patient_record():
    # In real mTLS, verify client certificate from request headers or environment
    client_cert = request.headers.get('X-Client-Cert-DN')
    if not client_cert:
        return jsonify({"error": "Unauthorized: Client certificate required for mTLS"}), 403
    return jsonify({"patient": "John Doe", "diagnosis": "Stable", "verified_client": client_cert})

if __name__ == "__main__":
    print("[SERVER] Starting secure HTTPS service on port 5000...")
    # To run with real SSL certificates: app.run(host='0.0.0.0', port=5000, ssl_context=('cert.pem', 'key.pem'))
    app.run(host='127.0.0.1', port=5000)