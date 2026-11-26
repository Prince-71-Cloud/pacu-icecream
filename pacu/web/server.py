#!/usr/bin/env python3
"""
Pacu Web GUI
============

A local browser front-end for the Pacu AWS exploitation framework.

It runs ONE real Pacu engine (pacu.Main) inside a single worker thread and
exposes it over HTTP:

  * Every action is routed through the real `Main.parse_command` dispatcher,
    so the GUI drives the actual framework - it does not re-implement anything.
  * Engine stdout / `Main.print` output is streamed to the browser over SSE.
  * Interactive module prompts (`Main.input` / builtin `input`) are relayed to
    the browser and answered via POST /api/input.

This binds to 127.0.0.1 by default. It gives full control of a security tool
that talks to real AWS accounts - do NOT expose it on an untrusted network.

Run:
    pacu-web                                # http://127.0.0.1:8088
    python -m pacu.web --port 9000 --host 127.0.0.1
"""
import argparse
import builtins
import importlib
import json
import queue
import sys
import threading
import traceback
from pathlib import Path

from flask import Flask, Response, abort, jsonify, request, send_file, send_from_directory

import pacu
import pacu.settings as settings
from pacu.core.lib import session_dir
from pacu.core.models import PacuSession, migrations
from pacu.utils import get_database_connection
from pacu.setup_database import setup_database_if_not_present

LOOT_MAX_BYTES = 2 * 1024 * 1024  # cap on a single file's returned content

HERE = Path(__file__).resolve().parent
PACU_PKG = Path(pacu.__file__).resolve().parent
MODULES_DIR = PACU_PKG / "modules"

# ----------------------------------------------------------------------------
# Inter-thread channels
# ----------------------------------------------------------------------------
_job_q: "queue.Queue" = queue.Queue()   # HTTP -> engine worker (serial)
_in_q: "queue.Queue" = queue.Queue()    # POST /api/input -> blocked prompt

# Output fan-out: each live SSE connection registers its own queue.
_subscribers: "set" = set()
_subscribers_lock = threading.Lock()

_real_stdout = sys.stdout
_engine_ready = threading.Event()
_awaiting_input = threading.Event()

_state_lock = threading.Lock()
# Serializes access to the shared SQLAlchemy Session (m.database), which is not thread-safe.
_db_lock = threading.RLock()
_last_snapshot = {"ready": False}  # cache so /api/state never blocks while the engine is busy
_main = None  # type: ignore  # populated by the worker thread


def emit(event_type: str, data=None) -> None:
    if isinstance(data, bytes):
        data = data.decode("utf-8", "replace")
    elif data is not None and not isinstance(data, str):
        data = str(data)
    evt = {"type": event_type, "data": data}
    with _subscribers_lock:
        targets = list(_subscribers)
    for q in targets:
        try:
            q.put_nowait(evt)
        except Exception:  # noqa: BLE001 - never let a slow/dead consumer block the engine
            pass


class _QueueWriter:
    """stdout replacement - forwards everything the engine prints to the browser."""

    def write(self, s):
        if s:
            if isinstance(s, bytes):
                s = s.decode("utf-8", "replace")
            emit("out", s)
        return len(s) if s else 0

    def flush(self):
        pass

    def isatty(self):
        return False


def _web_input(message: str = "") -> str:
    """input()/Main.input replacement - relays the prompt to the browser and blocks."""
    text = "" if message is None else str(message)
    # Drop any stale answers queued while no prompt was pending (e.g. double-clicked Send).
    try:
        while True:
            _in_q.get_nowait()
    except queue.Empty:
        pass
    if text:
        emit("out", text)
    emit("prompt", text)
    _awaiting_input.set()
    try:
        answer = _in_q.get()
    finally:
        _awaiting_input.clear()
    emit("out", (answer if answer is not None else "") + "\n")
    return answer if answer is not None else ""


# ----------------------------------------------------------------------------
# Engine worker thread
# ----------------------------------------------------------------------------
def _engine_worker():
    global _main
    sys.stdout = _QueueWriter()
    builtins.input = _web_input  # modules that call input() directly

    m = pacu.Main()
    m.input = lambda message="", *a, **k: _web_input(message)

    db_path = getattr(settings, "DATABASE_FILE_PATH", None) \
        or settings.DATABASE_CONNECTION_PATH.replace("sqlite:///", "")
    setup_database_if_not_present(db_path)
    m.database = get_database_connection(settings.DATABASE_CONNECTION_PATH)
    migrations(m.database)

    existing = m.database.query(PacuSession).all()
    active = next((s for s in existing if s.is_active), None)
    if active is None:
        if existing:
            m.activate_session(existing[0].name)
        else:
            s = m.new_session("web-session")
            s.activate(m.database)

    with _state_lock:
        _main = m
    _engine_ready.set()

    print("[pacu-web] Engine ready. Active session: {}".format(m.get_active_session().name))

    while True:
        job = _job_q.get()
        kind = job.get("kind")
        payload = job.get("payload")
        try:
            with _db_lock:   # the engine touches m.database; keep it off other threads
                if kind == "command":
                    m.parse_command(payload)
                elif kind == "set_keys":
                    # Empty access key / secret / token means "keep the current value"
                    # (matches the interactive set_keys for id/secret). Pacu's programmatic
                    # set_keys would otherwise clear an empty token, silently wiping temp creds.
                    sess = m.get_active_session()
                    m.set_keys(
                        key_alias=payload["alias"],
                        access_key_id=payload.get("access_key_id") or None,
                        secret_access_key=payload.get("secret_access_key") or None,
                        session_token=payload.get("session_token") or sess.session_token or None,
                    )
                    print("[pacu-web] Keys saved under alias '{}'.".format(payload["alias"]))
                elif kind == "new_session":
                    s = m.new_session(payload)
                    s.activate(m.database)
                    print("[pacu-web] Session '{}' created and activated.".format(payload))
                elif kind == "activate_session":
                    m.activate_session(payload)
                    print("[pacu-web] Switched to session '{}'.".format(payload))
                elif kind == "set_regions":
                    if payload.get("all"):
                        m.parse_set_regions_command(["set_regions", "all"])
                    else:
                        m.parse_set_regions_command(["set_regions"] + list(payload.get("regions", [])))
                else:
                    print("[pacu-web] Unknown job kind: {}".format(kind))
        except SystemExit:
            emit("out", "\n[pacu-web] (command exited)\n")
        except Exception as e:  # noqa: BLE001
            emit("out", "\n[pacu-web] Error: {}\n".format(e))
            emit("out", traceback.format_exc())
        finally:
            _job_q.task_done()
            emit("done", None)


# ----------------------------------------------------------------------------
# Module metadata (introspected from argparse, cached)
# ----------------------------------------------------------------------------
_modules_cache = None
_modules_lock = threading.Lock()


def _build_module_catalog():
    catalog = []
    for child in sorted(p for p in MODULES_DIR.iterdir() if (p / "main.py").exists()):
        name = child.name
        try:
            mod = importlib.import_module("pacu.modules.{}.main".format(name))
            info = mod.module_info
            args = []
            parser = getattr(mod, "parser", None)
            if parser is not None:
                for action in parser._actions:
                    if action.dest == "help" or not action.option_strings:
                        continue
                    args.append({
                        "flag": action.option_strings[0],
                        "dest": action.dest,
                        "is_switch": action.nargs == 0,
                        "required": bool(action.required),
                        "default": None if action.default in (None, False) else str(action.default),
                        "help": (action.help or "").strip(),
                        "choices": [str(c) for c in action.choices] if action.choices else None,
                    })
            catalog.append({
                "name": name,
                "category": info.get("category", "UNKNOWN"),
                "one_liner": info.get("one_liner", ""),
                "description": info.get("description", ""),
                "services": info.get("services", []),
                "args": args,
            })
        except Exception as e:  # noqa: BLE001
            catalog.append({
                "name": name, "category": "ERROR",
                "one_liner": "(failed to load: {})".format(e),
                "description": "", "services": [], "args": [],
            })
    return catalog


def get_module_catalog():
    global _modules_cache
    with _modules_lock:
        if _modules_cache is None:
            _modules_cache = _build_module_catalog()
        return _modules_cache


# ----------------------------------------------------------------------------
# Read-only state snapshot
# ----------------------------------------------------------------------------
def snapshot_state():
    global _last_snapshot
    with _state_lock:
        m = _main
    # Live engine flags never touch the DB, so they are always fresh.
    live = {
        "awaiting_input": _awaiting_input.is_set(),
        "engine_busy": _job_q.unfinished_tasks > 0,
    }
    if m is None:
        return {"ready": False, **live}
    # Reading session/keys/regions needs the shared DB Session. If the engine is mid-job
    # (holding _db_lock, possibly blocked on a prompt) don't block the poll: return the
    # last good snapshot with refreshed live flags.
    if not _db_lock.acquire(timeout=0.3):
        return {**_last_snapshot, **live, "db_busy": True}
    try:
        sess = m.get_active_session()
        snap = {
            "ready": True,
            "active_session": sess.name,
            "sessions": [s.name for s in m.database.query(PacuSession).all()],
            "key_alias": sess.key_alias,
            "access_key_id": sess.access_key_id,
            "has_secret": bool(sess.secret_access_key),
            "has_session_token": bool(sess.session_token),
            "regions": sess.session_regions if sess.session_regions else ["all"],
        }
    finally:
        _db_lock.release()
    _last_snapshot = snap
    return {**snap, **live}


# ----------------------------------------------------------------------------
# Flask app
# ----------------------------------------------------------------------------
app = Flask(__name__)


@app.after_request
def _no_cache(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/")
def index():
    return send_from_directory(HERE, "index.html")


@app.route("/api/state")
def api_state():
    return jsonify(snapshot_state())


@app.route("/api/modules")
def api_modules():
    return jsonify(get_module_catalog())


@app.route("/api/run", methods=["POST"])
def api_run():
    data = request.get_json(force=True)
    command = (data.get("command") or "").strip()
    if not command:
        return jsonify({"ok": False, "error": "empty command"}), 400
    emit("out", "\nPacu> {}\n".format(command))
    _job_q.put({"kind": "command", "payload": command})
    return jsonify({"ok": True})


@app.route("/api/keys", methods=["POST"])
def api_keys():
    data = request.get_json(force=True)
    alias = (data.get("alias") or "").strip()
    if len(alias) < 2:
        return jsonify({"ok": False, "error": "alias must be at least 2 characters"}), 400
    _job_q.put({"kind": "set_keys", "payload": {
        "alias": alias,
        "access_key_id": (data.get("access_key_id") or "").strip(),
        "secret_access_key": (data.get("secret_access_key") or "").strip(),
        "session_token": (data.get("session_token") or "").strip(),
    }})
    return jsonify({"ok": True})


@app.route("/api/session", methods=["POST"])
def api_session():
    data = request.get_json(force=True)
    action = data.get("action")
    name = (data.get("name") or "").strip()
    if action == "new":
        if not name:
            return jsonify({"ok": False, "error": "name required"}), 400
        # Reject duplicates up front: Main.new_session would otherwise fall into a
        # blocking input() loop in the worker and hang the engine.
        with _state_lock:
            m = _main
        if m is not None:
            with _db_lock:
                existing = {s.name for s in m.database.query(PacuSession).all()}
            if name in existing:
                return jsonify({"ok": False, "error": "a session named '{}' already exists".format(name)}), 400
        _job_q.put({"kind": "new_session", "payload": name})
    elif action == "activate":
        if not name:
            return jsonify({"ok": False, "error": "name required"}), 400
        _job_q.put({"kind": "activate_session", "payload": name})
    else:
        return jsonify({"ok": False, "error": "unknown action"}), 400
    return jsonify({"ok": True})


@app.route("/api/data")
def api_data():
    """The AWS service data Pacu has enumerated into the active session."""
    with _state_lock:
        m = _main
    if m is None:
        return jsonify({"ready": False, "data": {}})
    with _db_lock:
        sess = m.get_active_session()
        raw = sess.get_all_aws_data_fields_as_dict()
        name = sess.name
    # Force JSON-serializability (values can contain datetimes etc.)
    safe = json.loads(json.dumps(raw, default=str))
    return jsonify({"ready": True, "session": name, "services": safe})


_all_regions_cache = None


def _all_regions():
    global _all_regions_cache
    with _modules_lock:
        if _all_regions_cache is None:
            try:
                with open(MODULES_DIR / "service_regions.json") as f:
                    _all_regions_cache = sorted(json.load(f).get("all", []))
            except Exception:  # noqa: BLE001
                _all_regions_cache = []
        return _all_regions_cache


@app.route("/api/regions")
def api_regions():
    with _state_lock:
        m = _main
    if m is None:
        current = ["all"]
    else:
        with _db_lock:
            current = m.get_active_session().session_regions
    return jsonify({"all": _all_regions(), "current": current or ["all"]})


@app.route("/api/regions", methods=["POST"])
def api_set_regions():
    data = request.get_json(force=True)
    if data.get("all"):
        _job_q.put({"kind": "set_regions", "payload": {"all": True}})
        return jsonify({"ok": True})
    regions = [str(r).strip() for r in (data.get("regions") or []) if str(r).strip()]
    valid = set(_all_regions())
    bad = [r for r in regions if r not in valid]
    if bad:
        return jsonify({"ok": False, "error": "invalid region(s): " + ", ".join(bad)}), 400
    if not regions:
        return jsonify({"ok": False, "error": "select at least one region, or choose All"}), 400
    _job_q.put({"kind": "set_regions", "payload": {"regions": regions}})
    return jsonify({"ok": True})


def _session_root():
    # session_dir() reads the active session off the shared DB Session.
    with _db_lock:
        return Path(session_dir()).resolve()


def _resolve_loot(rel):
    """Resolve a session-relative loot path, confined to the session dir.

    Returns the resolved Path, or None if the path escapes the session root.
    """
    root = _session_root()
    target = (root / rel).resolve()
    if target != root and root not in target.parents:
        return None
    return target


@app.route("/api/loot")
def api_loot():
    """List every file written under the active session's directory (downloads, module data, logs)."""
    root = _session_root()
    files = []
    for p in root.rglob("*"):
        try:
            if p.is_file():
                st = p.stat()
                files.append({
                    "path": p.relative_to(root).as_posix(),
                    "size": st.st_size,
                    "mtime": int(st.st_mtime),
                })
        except OSError:
            continue
    files.sort(key=lambda f: f["mtime"], reverse=True)
    return jsonify({"root": str(root), "files": files})


@app.route("/api/loot/file")
def api_loot_file():
    """Return the content of one loot file, guarded against path traversal."""
    rel = request.args.get("path", "")
    target = _resolve_loot(rel)
    if target is None:
        return jsonify({"ok": False, "error": "path outside session"}), 400
    if not target.is_file():
        return jsonify({"ok": False, "error": "not a file"}), 404
    size = target.stat().st_size
    with open(target, "rb") as fh:          # read at most the cap; never load a huge file into RAM
        raw = fh.read(LOOT_MAX_BYTES)
    if b"\x00" in raw:  # looks binary
        return jsonify({"ok": True, "path": rel, "binary": True, "size": size, "text": None})
    return jsonify({
        "ok": True, "path": rel, "binary": False, "size": size,
        "truncated": size > LOOT_MAX_BYTES,
        "text": raw.decode("utf-8", "replace"),
    })


@app.route("/api/loot/download")
def api_loot_download():
    """Serve a loot file as a download attachment, guarded against path traversal."""
    rel = request.args.get("path", "")
    target = _resolve_loot(rel)
    if target is None:
        abort(400)
    if not target.is_file():
        abort(404)
    return send_file(str(target), as_attachment=True, download_name=target.name)


@app.route("/api/input", methods=["POST"])
def api_input():
    data = request.get_json(force=True)
    _in_q.put(str(data.get("value", "")))
    return jsonify({"ok": True})


@app.route("/api/stream")
def api_stream():
    def gen():
        q: "queue.Queue" = queue.Queue(maxsize=10000)
        with _subscribers_lock:
            _subscribers.add(q)
        try:
            q.put({"type": "hello", "data": "connected"})
            while True:
                try:
                    evt = q.get(timeout=20)
                except queue.Empty:
                    yield ": keep-alive\n\n"  # comment frame keeps the connection open
                    continue
                try:
                    payload = json.dumps(evt)
                except (TypeError, ValueError):
                    payload = json.dumps({"type": evt.get("type", "out"),
                                          "data": repr(evt.get("data"))})
                yield "data: {}\n\n".format(payload)
        finally:
            with _subscribers_lock:
                _subscribers.discard(q)
    return Response(gen(), mimetype="text/event-stream")


def main():
    ap = argparse.ArgumentParser(description="Pacu Web GUI")
    ap.add_argument("--host", default="127.0.0.1", help="bind host (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8088, help="bind port (default 8088)")
    args = ap.parse_args()

    worker = threading.Thread(target=_engine_worker, name="pacu-engine", daemon=True)
    worker.start()
    _engine_ready.wait(timeout=30)

    shown = "127.0.0.1" if args.host in ("0.0.0.0", "127.0.0.1") else args.host
    print("\n  Pacu Web GUI  ->  http://{}:{}\n".format(shown, args.port),
          file=_real_stdout, flush=True)
    if args.host not in ("127.0.0.1", "localhost"):
        print("  WARNING: binding to {} exposes full control of a live AWS attack tool.\n".format(args.host),
              file=_real_stdout, flush=True)

    app.run(host=args.host, port=args.port, threaded=True, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
