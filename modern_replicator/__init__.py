import hashlib
import pwd
import logging
import mmap
import os
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
from typing import Optional, Tuple

import click

CHUNK = 128 * 1024
DIRS = []
ALLOWED_HOSTS = {"files.pythonhosted.org", "mirror.osbeck.com"}

class Hasher:
    def __init__(self):
        self.blake_hasher = hashlib.blake2b(digest_size=32)
        self.sha256_hasher = hashlib.sha256()
    def update(self, chunk):
        self.blake_hasher.update(chunk)
        self.sha256_hasher.update(chunk)
    def save(self, filename):
        os.setxattr(filename, b"user.blake2b", self.blake_hasher.hexdigest().encode())
        os.setxattr(filename, b"user.sha256", self.sha256_hasher.hexdigest().encode())
        
class CacheEntry:
    def __init__(self, url):
        self.url = url
        # TODO validate for leading slash and ..
        self.rel = Path(url.split("://", 1)[1])
        self.cache_path = DIRS[0] / self.rel
        self.have_length = threading.Condition()
        self.mmap_created = threading.Event()
        self.file_complete = threading.Event()
        self.fd = None
        self.mmap = None
        self.length = None
        self.sofar = 0

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
        self.mmap = mmap.mmap(self.fd.fileno(), self.length, prot=mmap.PROT_READ)
        self.mmap_created.set()
        self.file_complete.set()
        return True

    def send_to_client(self, wfile, cur=0):
        self.mmap_created.wait()
        assert self.fd is not None, "send_to_client only after fd set"
        assert self.mmap is not None, "send_to_client only after mmap set"
        while True:
            if cur == self.length and self.file_complete.is_set():
                # print("bail")
                break
            rem = min(self.sofar - cur, CHUNK)

            if rem == 0:
                time.sleep(0.01)
                continue
            chunk = self.mmap[cur : cur + rem]

            try:
                wfile.write(chunk)
                wfile.flush()
            except ssl.SSLEOFError:
                break

            if rem != len(chunk):
                print("ERROR")
            cur += len(chunk)

    def save_to_disk(self, rfile, length):
        h = Hasher()
        with rfile:
            Path(self.cache_path).parent.mkdir(exist_ok=True, parents=True)
            assert self.fd is None, "Only call save_to_disk once"
            # TODO truncates for now, until I deal with header parsing more
            self.fd = open(
                self.cache_path.as_posix() + ".incomplete", "w+b", buffering=0
            )
            self.fd.seek(length, os.SEEK_SET)
            self.fd.truncate()

            self.mmap = mmap.mmap(self.fd.fileno(), length)
            self.mmap_created.set()
            cur = 0
            while True:
                chunk = rfile.read(CHUNK)
                h.update(chunk)
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
            h.save(self.cache_path.as_posix() + ".incomplete")
            os.setxattr(self.cache_path.as_posix() + ".incomplete", b"user.xdg.origin", self.url.encode("utf-8"))
            os.rename(self.cache_path.as_posix() + ".incomplete", self.cache_path)
            self.file_complete.set()
        else:
            print("ERROR", cur, length)


ACTIVE_CACHE = weakref.WeakValueDictionary()
ACTIVE_CACHE_LOCK = threading.Lock()


class ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
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
                    p = urllib.parse.urlparse(url)
                    # TODO Handle port
                    resp = urllib.request.urlopen(url)
                    length = int(resp.headers["content-length"])
                    ce.length = length

                    threading.Thread(
                        target=ce.save_to_disk, args=(resp, length),
                    ).start()

        self.send_response(200)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", ce.length)
        self.end_headers()
        ce.send_to_client(self.wfile)


def coserv(*servers):
    with socketserver._ServerSelector() as selector:
        for s in servers:
            selector.register(s, selectors.EVENT_READ)
        while True:
            ready = selector.select(10)
            for key, event in ready:
                key.fileobj._handle_request_noblock()


def run(
    bind,
    server_class=ThreadingHTTPServer,
    handler_class=ProxyHandler,
    ssl_cert=None,
    ssl_key=None,
):
    httpd = server_class(bind, handler_class)
    if ssl_key:
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
def main(ssl_cert, ssl_key, http_port, https_port, user, dirs):
    logging.basicConfig(level=logging.DEBUG)
    DIRS[:] = dirs.split(",")
    servers = [run(bind=("", http_port))]
    if ssl_key:
        servers.append(run(bind=("", https_port), ssl_cert=ssl_cert, ssl_key=ssl_key))
    if user:
        os.setuid(pwd.getpwnam(user).pw_uid)
    coserv(*servers)


if __name__ == "__main__":
    main()
