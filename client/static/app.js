const feed = document.getElementById("feed");
const historyBox = document.getElementById("history");
const statusEl = document.getElementById("status");
const statusSub = document.getElementById("status-sub");

let lastEventId = 0;

function addFeedItem(event) {
  const item = document.createElement("div");
  item.className = `feed-item ${event.kind}`;
  item.textContent = event.text;
  feed.prepend(item);
}

function renderHistory(messages) {
  historyBox.innerHTML = "";
  if (!messages.length) {
    const empty = document.createElement("div");
    empty.className = "feed-item system";
    empty.textContent = "No messages found yet.";
    historyBox.appendChild(empty);
    return;
  }
  messages.forEach((msg) => {
    const item = document.createElement("div");
    item.className = "feed-item message";
    item.textContent = msg;
    historyBox.appendChild(item);
  });
}

async function pollEvents() {
  try {
    const res = await fetch(`/api/events?since=${lastEventId}`);
    const data = await res.json();
    const events = data.events || [];
    events.forEach((event) => {
      lastEventId = Math.max(lastEventId, event.id);
      addFeedItem(event);
    });
    if (data.state) {
      if (data.state.logged_in) {
        statusEl.textContent = `Logged in as ${data.state.username}`;
        statusSub.textContent = "Ready to send secure messages.";
      } else if (data.state.last_status === "Registration Success") {
        statusEl.textContent = "Registration Success";
        statusSub.textContent = "Now log in to start chatting.";
      } else {
        statusEl.textContent = "Not logged in";
        statusSub.textContent = "Register or log in to start chatting.";
      }
    }
  } catch (err) {
    statusEl.textContent = "Disconnected";
    statusSub.textContent = "Unable to reach the server.";
  }
}

function bindForm(formId, endpoint, onSuccess) {
  const form = document.getElementById(formId);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formData = new FormData(form);
    const res = await fetch(endpoint, {
      method: "POST",
      body: formData,
    });
    const data = await res.json();
    if (onSuccess) {
      onSuccess(data);
    }
    form.reset();
  });
}

bindForm("register-form", "/api/register");
bindForm("login-form", "/api/login");
bindForm("send-form", "/api/send");
bindForm("logout-form", "/api/logout");
bindForm("delete-form", "/api/delete");
bindForm("history-form", "/api/history", (data) => {
  renderHistory(data.history || []);
});

pollEvents();
setInterval(pollEvents, 1500);
