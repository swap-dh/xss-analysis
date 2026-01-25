#!/usr/bin/env python3
import sys, json, traceback
from typing import Dict, Any, Optional
from xss_analyzer import analyze


# ---------- LSP stdio helpers ----------
def read_message() -> Optional[Dict[str, Any]]:
    headers = {}
    line = sys.stdin.buffer.readline()
    if not line:
        return None

    while line and line.strip():
        key, _, value = line.decode("utf-8", "replace").partition(":")
        headers[key.strip().lower()] = value.strip()
        line = sys.stdin.buffer.readline()

    content_length = int(headers.get("content-length", "0"))
    if content_length <= 0:
        return None

    body = sys.stdin.buffer.read(content_length)
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return None


def send_message(payload: Dict[str, Any]) -> None:
    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sys.stdout.buffer.write(f"Content-Length: {len(data)}\r\n\r\n".encode("ascii"))
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def reply(req: Dict[str, Any], result: Any = None, error: Any = None) -> None:
    resp = {"jsonrpc": "2.0", "id": req.get("id")}
    if error is not None:
        resp["error"] = error
    else:
        resp["result"] = result
    send_message(resp)


def notify(method: str, params: Any) -> None:
    send_message({"jsonrpc": "2.0", "method": method, "params": params})


# ---------- state ----------
docs: Dict[str, str] = {}  # uri -> text


def publish_xss_diagnostics(uri: str, text: str) -> None:
    diags = []
    for issue in analyze(text):
        diags.append({
            "range": {
                "start": {"line": issue.line, "character": issue.col},
                "end": {"line": issue.line, "character": issue.end_col},
            },
            "severity": issue.severity,  # 1=Error, 2=Warning
            "source": "xss-lsp",
            "message": issue.message,
        })

    notify("textDocument/publishDiagnostics", {"uri": uri, "diagnostics": diags})


# ---------- handlers ----------
def on_initialize(req: Dict[str, Any]) -> None:
    # Full sync: didChange가 "전체 텍스트"를 보냄
    result = {
        "capabilities": {
            "textDocumentSync": 1,  # Full
        }
    }
    reply(req, result)


def on_shutdown(req: Dict[str, Any]) -> None:
    reply(req, None)


def on_did_open(params: Dict[str, Any]) -> None:
    td = params["textDocument"]
    uri = td["uri"]
    text = td.get("text", "")
    docs[uri] = text
    publish_xss_diagnostics(uri, text)


def on_did_change(params: Dict[str, Any]) -> None:
    uri = params["textDocument"]["uri"]
    changes = params.get("contentChanges", [])
    if not changes:
        return
    text = changes[-1].get("text", "")
    docs[uri] = text
    publish_xss_diagnostics(uri, text)


def main() -> None:
    while True:
        msg = read_message()
        if msg is None:
            break

        try:
            method = msg.get("method")

            if method == "initialize":
                on_initialize(msg)
            elif method == "shutdown":
                on_shutdown(msg)
            elif method == "exit":
                break
            elif method == "textDocument/didOpen":
                on_did_open(msg.get("params", {}))
            elif method == "textDocument/didChange":
                on_did_change(msg.get("params", {}))
            else:
                # unknown request
                if "id" in msg:
                    reply(msg, error={"code": -32601, "message": f"Method not found: {method}"})

        except Exception:
            if "id" in msg:
                reply(msg, error={"code": -32603, "message": "Internal error"})
            traceback.print_exc(file=sys.stderr)


if __name__ == "__main__":
    main()