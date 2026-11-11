
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

class Server(BaseHTTPRequestHandler):

    def do_GET(self):
        cert = self.connection.getpeercert()

        self.send_response(200)
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.end_headers()

        if self.path == "/status":
            self.wfile.write(b"Public status: Running")

        elif self.path == "/patient":
            if cert:
                self.wfile.write(b"Access granted: Client authenticated")
            else:
                self.wfile.write(b"Access denied: Client certificate required")

        else:
            self.wfile.write(b"Page not found")

server = HTTPServer(("localhost", 8443), Server)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

context.load_cert_chain(
    "certs/server.crt",
    "certs/server.key"
)

context.load_verify_locations("certs/ca.crt")

context.verify_mode = ssl.CERT_OPTIONAL
context.minimum_version = ssl.TLSVersion.TLSv1_2

server.socket = context.wrap_socket(
    server.socket, server_side=True
)

print("HTTPS server running on port 8443")
server.serve_forever()
