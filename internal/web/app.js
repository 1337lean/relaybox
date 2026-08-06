"use strict";

const state = {
  selectedID: null,
  detail: null,
  events: null,
};

const elements = {
  copy: document.querySelector("#copy"),
  detail: document.querySelector("#detail"),
  list: document.querySelector("#list"),
  login: document.querySelector("#login"),
  replay: document.querySelector("#replay"),
  search: document.querySelector("#search"),
  status: document.querySelector("#status"),
  token: document.querySelector("#token"),
};

async function api(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) {
    throw new Error((await response.text()).trim() || response.statusText);
  }
  return response.status === 204 ? null : response.json();
}

function showStatus(message, isError = false) {
  elements.status.textContent = message;
  elements.status.classList.toggle("error", isError);
}

async function loadRequests() {
  const query = encodeURIComponent(elements.search.value);
  const page = await api(`/api/requests?q=${query}&limit=100`);

  elements.list.replaceChildren();
  if (page.items.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = "No requests yet.";
    elements.list.append(empty);
    return;
  }

  for (const request of page.items) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "item";
    button.textContent = `${request.Method} ${request.Path} · ${request.ID}`;
    button.addEventListener("click", () => showRequest(request.ID));
    elements.list.append(button);
  }
}

async function showRequest(id) {
  state.selectedID = id;
  state.detail = await api(`/api/requests/${encodeURIComponent(id)}`);
  elements.detail.className = "";
  elements.detail.textContent = JSON.stringify(state.detail, null, 2);
  elements.copy.disabled = false;
  elements.replay.disabled = false;
}

function startEventStream() {
  state.events?.close();
  state.events = new EventSource("/api/events");

  const eventNames = [
    "request.received",
    "attempt.finished",
    "forward.queued",
    "forward.succeeded",
    "forward.failed",
    "forward.fatal",
    "forward.poison",
  ];
  for (const name of eventNames) {
    state.events.addEventListener(name, async () => {
      try {
        await loadRequests();
        if (state.selectedID) {
          await showRequest(state.selectedID);
        }
      } catch (error) {
        showStatus(error.message, true);
      }
    });
  }
  state.events.addEventListener("error", () => {
    state.events?.close();
    window.setTimeout(async () => {
      try {
        await loadRequests();
        startEventStream();
      } catch (error) {
        showStatus(error.message, true);
      }
    }, 1_000);
  });
}

elements.login.addEventListener("click", async () => {
  try {
    await api("/api/session", {
      method: "POST",
      headers: { Authorization: `Bearer ${elements.token.value}` },
    });
    elements.token.value = "";
    await loadRequests();
    startEventStream();
    showStatus("Unlocked.");
  } catch (error) {
    showStatus(error.message, true);
  }
});

elements.token.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    elements.login.click();
  }
});

elements.copy.addEventListener("click", async () => {
  const body = state.detail.request.Body;
  const command = `printf '%s' '${body}' | base64 -d | curl --fail-with-body --request POST --header 'Content-Type: application/octet-stream' --data-binary @- http://127.0.0.1:8080/inbox`;
  try {
    await navigator.clipboard.writeText(command);
    showStatus("Safe curl command copied.");
  } catch (error) {
    showStatus(`Could not copy: ${error.message}`, true);
  }
});

elements.replay.addEventListener("click", async () => {
  try {
    await api(`/api/requests/${encodeURIComponent(state.selectedID)}/replay`, {
      method: "POST",
    });
    await showRequest(state.selectedID);
    showStatus("Replay scheduled.");
  } catch (error) {
    showStatus(error.message, true);
  }
});

let searchTimer;
elements.search.addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(async () => {
    try {
      await loadRequests();
    } catch (error) {
      showStatus(error.message, true);
    }
  }, 200);
});
