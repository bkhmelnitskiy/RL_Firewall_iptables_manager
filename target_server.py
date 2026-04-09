from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

HOST           = "0.0.0.0"
PORT           = 80
VALID_PASSWORD = "secret123"


class LoginHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/login":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode(errors="replace")
        params = urllib.parse.parse_qs(body)
        pwd    = params.get("password", [""])[0]

        if pwd == VALID_PASSWORD:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Login successful\n")
        else:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"Unauthorized\n")

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    print(f"Target server on {HOST}:{PORT}  (password: {VALID_PASSWORD})")
    HTTPServer((HOST, PORT), LoginHandler).serve_forever()
