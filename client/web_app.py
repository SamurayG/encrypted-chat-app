from flask import Flask, jsonify, render_template, request
import threading

import client as chat_client

app = Flask(__name__)

EVENTS = []
EVENT_LOCK = threading.Lock()
EVENT_ID = 0


def add_event(text, kind="system"):
    global EVENT_ID
    with EVENT_LOCK:
        EVENT_ID += 1
        EVENTS.append({"id": EVENT_ID, "kind": kind, "text": text})


def get_events_since(since_id):
    with EVENT_LOCK:
        return [event for event in EVENTS if event["id"] > since_id]


client = chat_client.ChatClient(on_event=add_event)
client.start_receiver()
add_event("Web UI started. Not logged in yet.", "system")


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/events")
def api_events():
    try:
        since = int(request.args.get("since", "0"))
    except ValueError:
        since = 0

    events = get_events_since(since)
    return jsonify({
        "events": events,
        "state": {
            "logged_in": client.logged_in,
            "username": client.username,
        }
    })


@app.post("/api/register")
def api_register():
    username = request.form.get("username", "")
    ok = client.register(username)
    return jsonify({"ok": ok})


@app.post("/api/login")
def api_login():
    username = request.form.get("username", "")
    ok = client.login(username)
    return jsonify({"ok": ok})


@app.post("/api/send")
def api_send():
    username = request.form.get("username", "")
    message = request.form.get("message", "")
    ok = client.send_message(username, message)
    return jsonify({"ok": ok})


@app.post("/api/history")
def api_history():
    username = request.form.get("username", "")
    history = client.view_history(username)
    return jsonify({"ok": True, "history": history})


@app.post("/api/delete")
def api_delete():
    username = request.form.get("username", "")
    ok = client.delete_history(username)
    return jsonify({"ok": ok})


@app.post("/api/logout")
def api_logout():
    client.logout()
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
