import hashlib
import io
import logging
import mmap
import os
import pwd
import re
import selectors
import socketserver
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
import weakref
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import IO
from typing import Optional, Tuple
from urllib.error import HTTPError

import click
import xattr

CHUNK = 128 * 1024
DIRS: list[Path] = []
ALLOWED_HOSTS = {"files.pythonhosted.org", "mirror.osbeck.com"}


class Hasher:
    def __init__(self) -> None:
        self.blake_hasher = hashlib.blake2b(digest_size=32)
        self.sha256_hasher = hashlib.sha256()

    def update(self, chunk: bytes) -> None:
        self.blake_hasher.update(chunk)
        self.sha256_hasher.update(chunk)

    def save(self, filename: str) -> None:
        xattr.setxattr(filename, "user.blake2b", self.blake_hasher.hexdigest().encode())
        xattr.setxattr(filename, "user.sha256", self.sha256_hasher.hexdigest().encode())


class CacheEntry:
    def __init__(self, url: str) -> None:
        self.url = url
        # TODO validate for leading slash and ..
        self.rel = Path(url.split("://", 1)[1])
        self.cache_path = DIRS[0] / self.rel
        if url.endswith("/"):
            self.cache_path /= "index.html"
        self.have_length = threading.Condition()
        self.mmap_created = threading.Event()
        self.file_complete = threading.Event()
        self.download_error = threading.Event()
        self.fd: IO[bytes] | None = None
        self.mmap: mmap.mmap | None = None
        self.length: int | None = None
        self.sofar: int = 0
        self.last_read_time = 0

    def find_incomplete(self) -> int:
        """Scan .incomplete file backwards in CHUNK blocks to find resume offset."""
        incomplete = Path(self.cache_path.as_posix() + ".incomplete")
        if not incomplete.exists():
            return 0
        size = incomplete.stat().st_size
        if size == 0:
            return 0
        with open(incomplete, "rb") as f:
            m = mmap.mmap(f.fileno(), size, prot=mmap.PROT_READ)
            offset = size
            while offset > 0:
                block_start = max(0, offset - CHUNK)
                if any(m[block_start:offset]):
                    return block_start
                offset = block_start
        return 0

    def check_already_cached(self) -> bool:
        """
        Call with have_length held
        """
        if not self.cache_path.exists():
            for d in DIRS:
                p = Path(d, self.rel)
                if p.exists():
                    self.cache_path = p
                    break
            else:
                return False

        print(self.cache_path, "from cache")
        self.fd = open(self.cache_path, "rb")
        self.length = self.cache_path.stat().st_size
        self.sofar = self.length
        if self.length != 0:
            self.mmap = mmap.mmap(self.fd.fileno(), self.length, prot=mmap.PROT_READ)
        self.mmap_created.set()
        self.file_complete.set()
        return True

    def send_to_client(self, wfile: io.BufferedIOBase, cur: int = 0) -> None:
        self.mmap_created.wait()
        if self.download_error.is_set():
            return
        assert self.fd is not None, "send_to_client only after fd set"
        assert self.mmap is not None, "send_to_client only after mmap set"
        self.last_read_time = time.monotonic()
        while True:
            if cur == self.length and self.file_complete.is_set():
                # print("bail")
                break
            if self.download_error.is_set() or self.length == 0:
                break
            rem = min(self.sofar - cur, CHUNK)

            if rem == 0:
                if time.monotonic() - self.last_read_time > 1:
                    return  # error, too slow
                time.sleep(0.1)
                print(time.monotonic() - self.last_read_time)
                continue
            chunk = self.mmap[cur : cur + rem]
            self.last_read_time = time.monotonic()

            try:
                wfile.write(chunk)
                wfile.flush()
            except ssl.SSLEOFError:
                break

            if rem != len(chunk):
                print("ERROR")
            cur += len(chunk)

    def save_to_disk(self, rfile: IO[bytes], length: int, start: int = 0) -> None:
        cur = start
        try:
            with rfile:
                Path(self.cache_path).parent.mkdir(exist_ok=True, parents=True)
                assert self.fd is None, "Only call save_to_disk once"
                incomplete = self.cache_path.as_posix() + ".incomplete"
                if start == 0:
                    # TODO truncates for now, until I deal with header parsing more
                    self.fd = open(incomplete, "w+b", buffering=0)
                    self.fd.seek(length, os.SEEK_SET)
                    self.fd.truncate()
                else:
                    self.fd = open(incomplete, "r+b", buffering=0)
                if length != 0:
                    self.mmap = mmap.mmap(self.fd.fileno(), length)
                self.sofar = start
                self.mmap_created.set()
                while True:
                    chunk = rfile.read(CHUNK)
                    if not chunk:
                        break
                    self.mmap[cur : cur + len(chunk)] = chunk
                    cur += len(chunk)
                    # print(cur, self.fd.tell())
                    self.sofar = cur
                    sys.stderr.write(".")
                    sys.stderr.flush()

            if cur == length:
                # rename and notify
                print("Rename", cur, length)
                incomplete = self.cache_path.as_posix() + ".incomplete"
                h = Hasher()
                for i in range(0, length, CHUNK):
                    h.update(self.mmap[i : i + CHUNK])
                h.save(incomplete)
                xattr.setxattr(incomplete, "user.xdg.origin", self.url.encode("utf-8"))
                os.rename(incomplete, self.cache_path)
                self.file_complete.set()
                return
        except Exception:
            pass

        print("ERROR", cur, length)
        self.mmap_created.set()  # unblock any waiters so they can see download_error
        self.download_error.set()
        with ACTIVE_CACHE_LOCK:
            if ACTIVE_CACHE.get(self.url) is self:
                del ACTIVE_CACHE[self.url]
        try:
            os.unlink(self.cache_path.as_posix() + ".incomplete")
        except OSError:
            pass


ACTIVE_CACHE: weakref.WeakValueDictionary[str, CacheEntry] = (
    weakref.WeakValueDictionary()
)
ACTIVE_CACHE_LOCK = threading.Lock()


class ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if not self.path.startswith("http"):
            url = "https://" + self.headers["host"] + self.path
        else:
            url = self.path.replace("http://", "https://")

        if urllib.parse.urlparse(url).hostname not in ALLOWED_HOSTS:
            self.send_response(403)
            self.end_headers()
            return

        with ACTIVE_CACHE_LOCK:
            ce = ACTIVE_CACHE.get(url)
            if ce is None:
                ce = ACTIVE_CACHE[url] = CacheEntry(url)

        with ce.have_length:
            if ce.length is None:
                cached = ce.check_already_cached()

                if not cached:
                    start = ce.find_incomplete()
                    req = urllib.request.Request(url)
                    if start:
                        req.add_header("Range", f"bytes={start}-")
                    resp = urllib.request.urlopen(req)
                    if start and resp.status == 206:
                        length = int(resp.headers["Content-Range"].split("/")[-1])
                    else:
                        length = int(resp.headers["content-length"])
                        start = 0
                    ce.length = length

                    threading.Thread(
                        target=ce.save_to_disk,
                        args=(resp, length, start),
                    ).start()

        assert ce.length is not None
        self.send_response(200)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(ce.length))
        self.end_headers()
        ce.send_to_client(self.wfile)


def coserv(*servers: ThreadingHTTPServer) -> None:
    with socketserver._ServerSelector() as selector:  # type: ignore[attr-defined]
        for s in servers:
            selector.register(s, selectors.EVENT_READ)
        while True:
            ready = selector.select(10)
            for key, event in ready:
                key.fileobj._handle_request_noblock()


def run(
    bind: tuple[str, int],
    server_class: type[ThreadingHTTPServer] = ThreadingHTTPServer,
    handler_class: type[BaseHTTPRequestHandler] = ProxyHandler,
    ssl_cert: str | None = None,
    ssl_key: str | None = None,
) -> ThreadingHTTPServer:
    httpd = server_class(bind, handler_class)
    if ssl_key:
        assert ssl_cert is not None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(ssl_cert, ssl_key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    return httpd


@click.command()
@click.option("--ssl-cert")
@click.option("--ssl-key")
@click.option("--http-port", default=80)
@click.option("--https-port", default=443)
@click.option("--user")
@click.option("--dirs")
def main(
    ssl_cert: str | None,
    ssl_key: str | None,
    http_port: int,
    https_port: int,
    user: str | None,
    dirs: str,
) -> None:
    logging.basicConfig(level=logging.DEBUG)
    DIRS[:] = [Path(d) for d in dirs.split(",")]
    servers = [run(bind=("", http_port))]
    if ssl_key:
        servers.append(run(bind=("", https_port), ssl_cert=ssl_cert, ssl_key=ssl_key))
    if user:
        os.setuid(pwd.getpwnam(user).pw_uid)
    coserv(*servers)


if __name__ == "__main__":
    main()
