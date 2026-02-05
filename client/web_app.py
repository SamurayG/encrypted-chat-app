from flask import Flask, jsonify, render_template, request, session
import os
import threading
import uuid

import client as chat_client

app = Flask(__name__)
app.secret_key = os.environ.get("WEB_UI_SECRET", "dev-secret-change-me")

SESSION_STATES = {}
SESSION_LOCK = threading.Lock()


def _new_state():
    state = {
        "events": [],
        "event_id": 0,
        "lock": threading.Lock(),
        "client": None,
    }
    return state


def _get_state():
    with SESSION_LOCK:
        sid = session.get("sid")
        if not sid:
            sid = uuid.uuid4().hex
            session["sid"] = sid
        state = SESSION_STATES.get(sid)
        if not state:
            state = _new_state()

            def add_event(text, kind="system"):
                with state["lock"]:
                    state["event_id"] += 1
                    state["events"].append({
                        "id": state["event_id"],
                        "kind": kind,
                        "text": text,
                    })

            client = chat_client.ChatClient(on_event=add_event)
            client.start_receiver()
            state["client"] = client
            add_event("Web UI started. Not logged in yet.", "system")
            SESSION_STATES[sid] = state
        return state


def _events_since(state, since_id):
    with state["lock"]:
        return [event for event in state["events"] if event["id"] > since_id]


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/events")
def api_events():
    try:
        since = int(request.args.get("since", "0"))
    except ValueError:
        since = 0

    state = _get_state()
    client = state["client"]
    events = _events_since(state, since)
    return jsonify({
        "events": events,
        "state": {
            "logged_in": client.logged_in,
            "username": client.username,
            "last_status": client.last_status,
        }
    })


@app.post("/api/register")
def api_register():
    state = _get_state()
    client = state["client"]
    username = request.form.get("username", "")
    ok = client.register(username)
    return jsonify({"ok": ok})


@app.post("/api/login")
def api_login():
    state = _get_state()
    client = state["client"]
    username = request.form.get("username", "")
    ok = client.login(username)
    return jsonify({"ok": ok})


@app.post("/api/send")
def api_send():
    state = _get_state()
    client = state["client"]
    username = request.form.get("username", "")
    message = request.form.get("message", "")
    ok = client.send_message(username, message)
    return jsonify({"ok": ok})


@app.post("/api/history")
def api_history():
    state = _get_state()
    client = state["client"]
    username = request.form.get("username", "")
    history = client.view_history(username)
    return jsonify({"ok": True, "history": history})


@app.post("/api/delete")
def api_delete():
    state = _get_state()
    client = state["client"]
    username = request.form.get("username", "")
    ok = client.delete_history(username)
    return jsonify({"ok": ok})


@app.post("/api/logout")
def api_logout():
    state = _get_state()
    client = state["client"]
    client.logout()
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
