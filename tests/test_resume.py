import io
import mmap as mmap_module
import os
import tempfile
import threading
import urllib.request
from pathlib import Path
from unittest.mock import patch

import modern_replicator

import pytest
from modern_replicator import ACTIVE_CACHE, CacheEntry, CHUNK


URL = "https://files.pythonhosted.org/packages/test.whl"


@pytest.fixture(autouse=True)
def reset_dirs(tmp_path):
    modern_replicator.DIRS[:] = [str(tmp_path)]
    yield


@pytest.fixture
def ce():
    return CacheEntry(URL)


def write_incomplete(ce, data, total_length):
    path = ce.cache_path.as_posix() + ".incomplete"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w+b") as f:
        f.seek(total_length - 1)
        f.write(b"\x00")
        f.seek(0)
        if data:
            f.write(data)
    return path


# --- find_incomplete ---


def test_find_incomplete_no_file(ce):
    assert ce.find_incomplete() == 0


def test_find_incomplete_empty_file(ce):
    """Zero-byte .incomplete file — resume from 0."""
    path = ce.cache_path.as_posix() + ".incomplete"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w").close()  # empty file
    assert ce.find_incomplete() == 0


def test_find_incomplete_all_zeros(ce):
    """Nothing downloaded yet — should resume from 0."""
    write_incomplete(ce, b"", CHUNK * 4)
    assert ce.find_incomplete() == 0


def test_find_incomplete_one_chunk(ce):
    """Exactly one chunk downloaded — last non-zero block starts at 0."""
    data = bytes(range(256)) * (CHUNK // 256)
    write_incomplete(ce, data, CHUNK * 4)
    assert ce.find_incomplete() == 0


def test_find_incomplete_partial_second_chunk(ce):
    """1.5 chunks downloaded — resume offset is start of second block."""
    data = b"\x01" * (CHUNK + CHUNK // 2)
    write_incomplete(ce, data, CHUNK * 4)
    assert ce.find_incomplete() == CHUNK


def test_find_incomplete_data_ends_with_zeros(ce):
    """Payload legitimately ends with zeros — must not skip into unwritten region."""
    chunk1 = b"\x01" * CHUNK
    chunk2 = b"\x01" * (CHUNK // 2) + b"\x00" * (CHUNK // 2)
    write_incomplete(ce, chunk1 + chunk2, CHUNK * 3)
    # Last non-zero block is chunk2, so resume from CHUNK
    assert ce.find_incomplete() == CHUNK


# --- save_to_disk: fresh download ---


def test_save_to_disk_fresh(ce):
    """Normal start=0 path creates file, writes data, renames on completion."""
    data = b"\x42" * 5000
    ce.length = len(data)
    ce.save_to_disk(io.BytesIO(data), len(data))

    assert ce.file_complete.is_set()
    assert not ce.download_error.is_set()
    assert ce.cache_path.exists()
    assert not Path(ce.cache_path.as_posix() + ".incomplete").exists()
    assert ce.cache_path.read_bytes() == data


def test_save_to_disk_fresh_error(ce):
    """Broken rfile on fresh download sets error flag and cleans up."""

    class BrokenFile:
        def read(self, n):
            raise OSError("network died")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    incomplete = ce.cache_path.as_posix() + ".incomplete"
    with patch.dict(ACTIVE_CACHE, {URL: ce}):
        ce.length = 5000
        ce.save_to_disk(BrokenFile(), 5000)

    assert ce.download_error.is_set()
    assert not ce.file_complete.is_set()
    assert not Path(incomplete).exists()


# --- save_to_disk: resume ---


def test_resume_completes_file(ce):
    """save_to_disk(start=CHUNK) splices in the remaining bytes correctly."""
    total = CHUNK * 3
    first_part = b"\xAB" * CHUNK
    second_part = b"\xCD" * (CHUNK * 2)

    write_incomplete(ce, first_part, total)

    ce.length = total
    ce.save_to_disk(io.BytesIO(second_part), total, start=CHUNK)

    assert ce.file_complete.is_set()
    assert not ce.download_error.is_set()
    assert ce.cache_path.exists()
    assert not Path(ce.cache_path.as_posix() + ".incomplete").exists()

    content = ce.cache_path.read_bytes()
    assert content[:CHUNK] == first_part
    assert content[CHUNK:] == second_part


def test_save_to_disk_truncated_read(ce):
    """rfile ends early with no exception (cur < length) — sets error, cleans up."""
    data = b"\x42" * 100  # only 100 bytes, but we claim 1000
    with patch.dict(ACTIVE_CACHE, {URL: ce}):
        ce.length = 1000
        ce.save_to_disk(io.BytesIO(data), 1000)

    assert ce.download_error.is_set()
    assert not ce.file_complete.is_set()
    assert not Path(ce.cache_path.as_posix() + ".incomplete").exists()


def test_save_to_disk_error_ce_not_in_cache(ce):
    """Error path when ce was already evicted from ACTIVE_CACHE — no KeyError."""

    class BrokenFile:
        def read(self, n):
            raise OSError("gone")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    # Don't add ce to ACTIVE_CACHE — covers the `is self` False branch
    ce.length = 5000
    ce.save_to_disk(BrokenFile(), 5000)

    assert ce.download_error.is_set()


def test_resume_error_sets_flag_and_cleans_up(ce):
    """A broken resume sets download_error and removes .incomplete."""
    total = CHUNK * 2
    write_incomplete(ce, b"\x01" * CHUNK, total)
    incomplete = ce.cache_path.as_posix() + ".incomplete"

    class BrokenFile:
        def read(self, n):
            raise OSError("network died")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    with patch.dict(ACTIVE_CACHE, {URL: ce}):
        ce.length = total
        ce.save_to_disk(BrokenFile(), total, start=CHUNK)

    assert ce.download_error.is_set()
    assert not ce.file_complete.is_set()
    assert not Path(incomplete).exists()


# --- send_to_client ---


def _setup_ce_with_data(ce, data):
    """Populate a CacheEntry as if check_already_cached had run."""
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(data)
    tmp.flush()
    ce.fd = tmp
    ce.length = len(data)
    ce.sofar = len(data)
    ce.mmap = mmap_module.mmap(tmp.fileno(), len(data), prot=mmap_module.PROT_READ)
    ce.mmap_created.set()
    ce.file_complete.set()


def test_send_to_client_complete(ce):
    """send_to_client streams the full content to wfile."""
    data = b"\xAB" * 5000
    _setup_ce_with_data(ce, data)

    buf = io.BytesIO()
    ce.send_to_client(buf)
    assert buf.getvalue() == data


def test_send_to_client_ssl_eof(ce):
    """SSLEOFError during write causes clean exit."""
    import ssl

    data = b"\xAB" * 5000
    _setup_ce_with_data(ce, data)

    class SSLFile:
        def write(self, chunk):
            raise ssl.SSLEOFError

        def flush(self):
            pass

    ce.send_to_client(SSLFile())  # should return without hanging


def test_send_to_client_download_error_before_mmap(ce):
    """If download_error fires before mmap_created, send_to_client returns immediately."""
    ce.download_error.set()
    ce.mmap_created.set()  # unblocks the wait
    buf = io.BytesIO()
    ce.send_to_client(buf)
    assert buf.getvalue() == b""


def test_send_to_client_download_error_mid_stream(ce):
    """download_error set while streaming causes loop to exit."""
    data = b"\x01" * 5000
    _setup_ce_with_data(ce, data)
    ce.file_complete.clear()  # not complete yet

    written = []

    class SlowFile:
        def write(self, chunk):
            written.append(chunk)
            # trigger error after first write
            ce.download_error.set()

        def flush(self):
            pass

    ce.send_to_client(SlowFile())
    assert len(written) >= 1  # wrote at least something before stopping


def test_send_to_client_streams_while_downloading(ce):
    """send_to_client can stream data while save_to_disk is still writing."""
    total = 5000
    data = b"\xCC" * total

    ce.length = total  # normally set by do_GET before the thread starts
    rfile = io.BytesIO(data)
    t = threading.Thread(target=ce.save_to_disk, args=(rfile, total))
    t.start()

    buf = io.BytesIO()
    ce.send_to_client(buf)
    t.join()

    assert ce.file_complete.is_set()
    assert buf.getvalue() == data


# --- check_already_cached ---


def test_check_already_cached_primary(ce, tmp_path):
    """Finds completed file in primary DIRS entry."""
    os.makedirs(ce.cache_path.parent, exist_ok=True)
    ce.cache_path.write_bytes(b"\x01" * 100)

    with ce.have_length:
        result = ce.check_already_cached()

    assert result is True
    assert ce.length == 100
    assert ce.file_complete.is_set()


def test_check_already_cached_secondary(tmp_path):
    """Finds completed file in a secondary DIRS entry."""
    primary = tmp_path / "primary"
    secondary = tmp_path / "secondary"
    primary.mkdir()
    secondary.mkdir()
    modern_replicator.DIRS[:] = [str(primary), str(secondary)]

    ce = CacheEntry(URL)
    # Write to secondary only
    rel = Path(URL.split("://", 1)[1])
    dest = secondary / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(b"\x02" * 200)

    with ce.have_length:
        result = ce.check_already_cached()

    assert result is True
    assert ce.length == 200
    assert ce.cache_path == dest


def test_check_already_cached_miss(ce):
    """Returns False when file is not in any DIRS entry."""
    with ce.have_length:
        result = ce.check_already_cached()
    assert result is False


# --- httpbin integration ---

HTTPBIN = "https://httpbin.org"
TOTAL = 9000
SPLIT = 3000  # resume offset — directly used, not from find_incomplete


def test_range_request_httpbin():
    """httpbin /range/{n} supports Range headers — verify 206 plumbing."""
    req = urllib.request.Request(f"{HTTPBIN}/range/{TOTAL}")
    req.add_header("Range", f"bytes={SPLIT}-")
    resp = urllib.request.urlopen(req)

    assert resp.status == 206
    total = int(resp.headers["Content-Range"].split("/")[-1])
    assert total == TOTAL

    body = resp.read()
    assert len(body) == TOTAL - SPLIT


def test_full_resume_via_httpbin(tmp_path):
    """End-to-end: pre-populate .incomplete then resume via httpbin /range."""
    modern_replicator.DIRS[:] = [str(tmp_path)]
    url = f"{HTTPBIN}/range/{TOTAL}"

    # Download the first SPLIT bytes
    first_resp = urllib.request.urlopen(
        urllib.request.Request(url, headers={"Range": f"bytes=0-{SPLIT - 1}"})
    )
    first_bytes = first_resp.read()
    assert len(first_bytes) == SPLIT

    ce = CacheEntry(url)
    incomplete = ce.cache_path.as_posix() + ".incomplete"
    os.makedirs(os.path.dirname(incomplete), exist_ok=True)
    with open(incomplete, "w+b") as f:
        f.seek(TOTAL - 1)
        f.write(b"\x00")
        f.seek(0)
        f.write(first_bytes)

    # Resume directly from SPLIT (find_incomplete would return 0 since TOTAL < CHUNK,
    # but the save_to_disk/Range machinery is what we're testing here)
    req = urllib.request.Request(url)
    req.add_header("Range", f"bytes={SPLIT}-")
    resp = urllib.request.urlopen(req)
    assert resp.status == 206
    total = int(resp.headers["Content-Range"].split("/")[-1])
    assert total == TOTAL

    ce.length = total
    ce.save_to_disk(resp, total, start=SPLIT)

    assert ce.file_complete.is_set()
    assert ce.cache_path.exists()
    assert ce.cache_path.stat().st_size == TOTAL
