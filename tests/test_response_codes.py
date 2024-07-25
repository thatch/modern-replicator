import time
import tempfile
from pathlib import Path
from io import BytesIO
from modern_replicator import ProxyHandler, ALLOWED_HOSTS, DIRS

class ConnectionFake:
    def __init__(self, buf: bytes):
        self.rfile = BytesIO(buf)
        self.wfile = BytesIO()
    def makefile(self, mode, bufsize):
        if "r" in mode:
            return self.rfile
        elif "w" in mode:
            return self.wfile
        else:
            raise ValueError(f"Unknown mode {mode}")

    def sendall(self, b):
        self.wfile.write(b)

def test_200():
    ALLOWED_HOSTS.add("httpbin.org")
    with tempfile.TemporaryDirectory(delete=False) as td:
        DIRS[:] = [td]
        conn = ConnectionFake(
            b"GET /status/200 HTTP/1.0\r\nHost: httpbin.org\r\n\r\n",
        )
        ProxyHandler(conn, ("127.0.0.1", 1234), None)
        lines = conn.wfile.getvalue().decode("latin-1").splitlines()
        assert lines[0] == "HTTP/1.0 200 OK"
        # 1 Server
        # 2 Date
        assert lines[3] == "Connection: close"
        assert lines[4] == "Content-Length: 0"
        assert lines[5] == ""
        p = Path(td, "httpbin.org", "status", "200")
        while not p.exists():
            time.sleep(0.1)
        assert p.read_text() == ""
    

def test_404():
    ALLOWED_HOSTS.add("httpbin.org")
    with tempfile.TemporaryDirectory() as td:
        DIRS[:] = [td]
        conn = ConnectionFake(
            b"GET /status/404 HTTP/1.0\r\nHost: httpbin.org\r\n\r\n",
        )
        ProxyHandler(conn, ("127.0.0.1", 1234), None)
        lines = conn.wfile.getvalue().decode("latin-1").splitlines()
        assert lines[0] == "HTTP/1.0 404 Not Found"
        # 1 Server
        # 2 Date
        p = Path(td, "httpbin.org", "status", "404")
        assert not p.exists()

def test_dir_index():
    ALLOWED_HOSTS.add("timhatch.com")
    with tempfile.TemporaryDirectory(delete=False) as td:
        DIRS[:] = [td]
        conn = ConnectionFake(
            b"GET /ex/2006/12/ HTTP/1.0\r\nHost: timhatch.com\r\n\r\n",
        )
        ProxyHandler(conn, ("127.0.0.1", 1234), None)
        lines = conn.wfile.getvalue().decode("latin-1").splitlines()
        assert lines[0] == "HTTP/1.0 200 OK"
        assert b"Index of /ex/2006/12" in conn.wfile.getvalue()
        index = Path(td, "timhatch.com", "ex", "2006", "12", "index.html")
        assert "Index of /ex/2006/12" in index.read_text()
