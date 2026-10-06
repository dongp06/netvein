# netvein_addon.py — thin control servant for netvein-mcp traffic tools.
# Runs inside mitmdump. All shaping/filtering lives in the Node process;
# this file only owns flow capture, hold mechanics, replay and export.
# NOTE: held-flow notifications are poll-based (stats/list), not pushed.
import asyncio
import base64
import hashlib
import json
import os
import re
import ssl
import time
import urllib.request

MAX_BODY = 20000
STORE_CAP = 2000  # ring cap; held flows are never evicted


def env(name, default):
    return os.environ.get(name, default)


def iso(ts):
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + "Z"
    except Exception:
        return ""


def summary(flow):
    req = flow.request
    resp = getattr(flow, "flow_response", None) or flow.response
    # pretty_host omits the port; non-default ports must ride along or curl/
    # list targets the wrong endpoint.
    default_port = 443 if req.scheme == "https" else 80
    host = req.pretty_host if req.port == default_port else f"{req.pretty_host}:{req.port}"
    duration = 0
    if req.timestamp_end and req.timestamp_start:
        duration = int((req.timestamp_end - req.timestamp_start) * 1000)
    return {
        "id": flow.id, "ts": iso(req.timestamp_start), "method": req.method,
        "host": host, "path": req.path,
        "status": resp.status_code if resp else None,
        "bytes": len(resp.raw_content) if resp and resp.raw_content else 0,
        "durationMs": duration, "held": getattr(flow, "netvein_held", False),
        "expired": getattr(flow, "netvein_expired", False), "scheme": req.scheme,
    }


def detail(flow):
    def headers(msg):
        return {k.lower(): v for k, v in msg.headers.items(multi=True)} if msg else {}

    def body(msg):
        if msg is None or msg.raw_content is None:
            return None
        try:
            text = msg.get_text(strict=False)
        except Exception:
            return None
        return text[:MAX_BODY] if text else None

    out = {
        "summary": summary(flow),
        "request": {"headers": headers(flow.request), "body": body(flow.request)},
        "response": {
            "headers": headers(flow.response), "body": body(flow.response),
            "status": flow.response.status_code if flow.response else None,
        } if flow.response else None,
    }
    if flow.websocket:
        # mitmproxy 11: WebSocketData.messages, content is bytes.
        out["wsFrames"] = [
            {"dir": "up" if m.from_client else "down", "ts": iso(m.timestamp),
             "payload": (m.content.decode("utf-8", "replace") if m.content else "")[:512]}
            for m in flow.websocket.messages[:200]
        ]
    return out


class Netvein:
    def __init__(self):
        self.flows = {}        # id -> flow
        self.order = []        # ids, oldest first
        self.breakpoints = []  # {"pattern": compiled, "maxHoldMs": int, "count": int}
        self.hold_events = {}  # flow id -> asyncio.Event
        self.decisions = {}    # flow id -> {"action","patch"}
        self.server = None
        self.start = time.time()
        self.spki = self._spki()
        self.capture_path = env("NETVEIN_CAPTURE", "")
        self.capture_fh = None

    def _spki(self):
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            pem_path = os.path.join(env("NETVEIN_CONFDIR", os.path.expanduser("~/.mitmproxy")), "mitmproxy-ca-cert.pem")
            with open(pem_path, "rb") as fh:
                cert = x509.load_pem_x509_certificate(fh.read())
            der = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            return base64.b64encode(hashlib.sha256(der).digest()).decode()
        except Exception:
            return None

    # ---- mitmproxy hooks -------------------------------------------------
    def response(self, flow):
        self._remember(flow)
        self._capture(flow)

    def error(self, flow):
        self._remember(flow)
        self._capture(flow)

    def websocket_message(self, flow):
        self._remember(flow)

    def websocket_end(self, flow):
        self._remember(flow)
        # Frames are complete now: append a second, richer line (last wins per id).
        self._capture(flow, force=True)

    async def request(self, flow):
        for bp in self.breakpoints:
            if bp["pattern"].search(flow.request.pretty_url):
                flow.netvein_held = True
                bp["count"] += 1
                event = asyncio.Event()
                self.hold_events[flow.id] = event
                self._remember(flow)
                asyncio.ensure_future(self._expire(flow, bp["maxHoldMs"]))
                await event.wait()
                decision = self.decisions.pop(flow.id, {"action": "pass"})
                flow.netvein_held = False
                self._apply(flow, decision)
                return

    async def _expire(self, flow, ms):
        try:
            await asyncio.sleep(ms / 1000)
        except asyncio.CancelledError:
            return
        if flow.id in self.hold_events:
            flow.netvein_expired = True
            self.decisions[flow.id] = {"action": "pass"}
            self.hold_events.pop(flow.id).set()

    def _apply(self, flow, decision):
        action = decision.get("action", "pass")
        patch = decision.get("patch") or {}
        if action == "drop":
            flow.kill()
            return
        if action == "modify":
            req = flow.request
            if "url" in patch:
                req.url = patch["url"]
            if "method" in patch:
                req.method = patch["method"]
            for k, v in (patch.get("headers") or {}).items():
                req.headers[k] = v
            if "body" in patch:
                req.set_text(patch["body"])

    def _capture(self, flow, force=False):
        if not self.capture_path:
            return
        if not force and getattr(flow, "netvein_captured", False):
            return
        if self.capture_fh is None:
            try:
                self.capture_fh = open(self.capture_path, "a", buffering=1)
            except Exception:
                self.capture_path = ""  # never let disk trouble break capture service
                return
        try:
            self.capture_fh.write(json.dumps(detail(flow)) + "\n")
            flow.netvein_captured = True
        except Exception:
            pass

    def _remember(self, flow):
        if flow.id not in self.flows:
            self.order.append(flow.id)
            while len(self.order) > STORE_CAP:
                oldest = self.order.pop(0)
                if not getattr(self.flows.get(oldest), "netvein_held", False):
                    self.flows.pop(oldest, None)
                else:
                    self.order.insert(0, oldest)
                    break
        self.flows[flow.id] = flow

    # ---- control socket ---------------------------------------------------
    async def running(self):
        port = int(env("NETVEIN_CTL_PORT", "0"))
        self.server = await asyncio.start_server(self._client, "127.0.0.1", port)
        actual = self.server.sockets[0].getsockname()[1]
        with open(env("NETVEIN_PORTFILE", "/tmp/netvein-mcp-ctl.port"), "w") as fh:
            fh.write(str(actual))

    async def _client(self, reader, writer):
        buffer = b""
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if line.strip():
                        reply = await self._handle(line.decode())
                        writer.write((json.dumps(reply) + "\n").encode())
                        await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _handle(self, line):
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            return {"ok": False, "error": "bad json"}
        cmd, args, rid = msg.get("cmd"), msg.get("args") or {}, msg.get("id")
        handler = getattr(self, "_cmd_" + str(cmd), None)
        if not handler:
            return {"id": rid, "ok": False, "error": "unknown command " + str(cmd)}
        try:
            return {"id": rid, "ok": True, **(await handler(args))}
        except LookupError as exc:
            return {"id": rid, "ok": False, "error": "flow not found: " + str(exc)}
        except Exception as exc:  # protocol must never crash the daemon
            return {"id": rid, "ok": False, "error": f"{type(exc).__name__}: {exc}"}

    def _filter(self, flows, args):
        host = (args.get("host") or "").lower()
        path_contains = args.get("pathContains") or ""
        method = (args.get("method") or "").upper()
        status = args.get("status")
        held_only = args.get("heldOnly")
        since = args.get("since")
        limit = min(max(int(args.get("limit") or 50), 1), 500)
        out = []
        for f in flows:
            s = summary(f)
            if host and host not in s["host"].lower():
                continue
            if path_contains and path_contains not in s["path"]:
                continue
            if method and s["method"].upper() != method:
                continue
            if status is not None and s["status"] != status:
                continue
            if held_only and not s["held"]:
                continue
            if since and s["ts"] and s["ts"] < since:
                continue
            out.append(s)
        return out[-limit:]

    async def _cmd_list(self, args):
        # _filter already returns serialized summaries; do not re-summarize.
        return {"flows": self._filter(list(self.flows.values()), args)}

    async def _cmd_get(self, args):
        flow = self.flows.get(args["flowId"])
        if not flow:
            raise LookupError(str(args.get("flowId")))
        return {"detail": detail(flow)}

    async def _cmd_breakpoint_set(self, args):
        self.breakpoints.append({
            "pattern": re.compile(args["pattern"]),
            "maxHoldMs": int(args.get("maxHoldMs") or 60000),
            "count": 0,
        })
        return {"count": len(self.breakpoints)}

    async def _cmd_breakpoints(self, args):
        return {"breakpoints": [
            {"index": i, "pattern": bp["pattern"].pattern, "maxHoldMs": bp["maxHoldMs"], "hits": bp["count"]}
            for i, bp in enumerate(self.breakpoints)
        ]}

    async def _cmd_breakpoint_release(self, args):
        flow_id = args["flowId"]
        if flow_id not in self.hold_events:
            raise LookupError(flow_id)
        self.decisions[flow_id] = {"action": args.get("action", "pass"), "patch": args.get("patch")}
        self.hold_events.pop(flow_id).set()
        return {"released": flow_id}

    async def _cmd_replay(self, args):
        flow = self.flows.get(args["flowId"])
        if not flow:
            raise LookupError(str(args.get("flowId")))
        req = flow.request
        overrides = args.get("overrides") or {}
        url = overrides.get("url") or req.pretty_url
        method = overrides.get("method") or req.method
        headers = {k: v for k, v in req.headers.items(multi=True) if k.lower() not in ("host", "connection")}
        headers.update({k.lower(): v for k, v in (overrides.get("headers") or {}).items()})
        try:
            body = overrides.get("body", req.get_text(strict=False))
        except Exception:
            body = None
        request = urllib.request.Request(
            url, data=body.encode() if body is not None else None, method=method,
            headers={k: str(v) for k, v in headers.items()})

        def send():
            # RE context: replay targets may present certs this CA cannot verify;
            # verification is deliberately off for out-of-page replay.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # Spec §1: replay goes through the proxy so it lands in the flow
            # store and honors --allow-hosts. No proxyPort => direct.
            handlers = []
            proxy_port = args.get("proxyPort")
            if proxy_port:
                handlers.append(urllib.request.ProxyHandler(
                    {"http": f"http://127.0.0.1:{proxy_port}", "https": f"http://127.0.0.1:{proxy_port}"}))
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), *handlers)
            try:
                with opener.open(request, timeout=15) as resp:
                    return {"status": resp.status,
                            "headers": {k.lower(): v for k, v in resp.headers.items()},
                            "body": resp.read(MAX_BODY + 1)[:MAX_BODY].decode("utf-8", "replace")}
            except Exception as exc:
                return {"status": getattr(exc, "code", None), "headers": {}, "body": None, "error": str(exc)}

        result = await asyncio.get_event_loop().run_in_executor(None, send)
        return {"replay": result}

    async def _cmd_export(self, args):
        fmt = args.get("format", "har")
        path = args["path"]

        def build_har():
            entries = []
            for f in self.flows.values():
                if not f.response:
                    continue
                s = summary(f)
                entries.append({
                    "startedDateTime": s["ts"], "time": s["durationMs"],
                    "request": {
                        "method": f.request.method, "url": f.request.pretty_url, "httpVersion": "HTTP/1.1",
                        "headers": [{"name": k, "value": v} for k, v in f.request.headers.items(multi=True)],
                        "queryString": [], "cookies": [], "headersSize": -1,
                        "bodySize": len(f.request.raw_content or b""),
                    },
                    "response": {
                        "status": f.response.status_code, "statusText": f.response.reason or "", "httpVersion": "HTTP/1.1",
                        "headers": [{"name": k, "value": v} for k, v in f.response.headers.items(multi=True)], "cookies": [],
                        "content": {
                            "size": len(f.response.raw_content or b""),
                            "mimeType": f.response.headers.get("content-type", "application/octet-stream"),
                            "text": (f.response.get_text(strict=False) or "")[:MAX_BODY],
                        },
                        "headersSize": -1, "bodySize": len(f.response.raw_content or b""),
                    },
                    "cache": {}, "timings": {"send": 0, "wait": s["durationMs"], "receive": 0},
                })
            return {"log": {"version": "1.2", "creator": {"name": "netvein-mcp", "version": env("NETVEIN_VERSION", "unknown")}, "entries": entries}}

        lines = []
        skipped = 0
        if fmt == "jsonl":
            for f in self.flows.values():
                try:
                    lines.append(json.dumps(detail(f)))
                except Exception:
                    skipped += 1
            with open(path, "w") as fh:
                fh.write("\n".join(lines) + ("\n" if lines else ""))
        elif fmt == "har":
            # serialize fully before touching disk: a bad flow must not leave a
            # partial file behind.
            payload = json.dumps(build_har())
            with open(path, "w") as fh:
                fh.write(payload)
        else:
            raise ValueError("unknown export format")
        return {"path": path, "count": len(self.flows) - skipped, "skipped": skipped}

    async def _cmd_stats(self, args):
        held = list(self.hold_events.keys())
        return {"running": True, "flows": len(self.flows), "held": held,
                "breakpoints": len(self.breakpoints), "uptimeS": int(time.time() - self.start), "spki": self.spki,
                "capture": self.capture_path or None}

    async def _cmd_stop(self, args):
        asyncio.get_event_loop().call_later(0.1, lambda: os._exit(0))
        return {"stopping": True}


addons = [Netvein()]
