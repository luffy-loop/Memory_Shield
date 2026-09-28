const $ = (id) => document.getElementById(id);

const api = async (url, options = {}) => {
    const response = await fetch(url, options);

    if (!response.ok) {
        throw new Error(await response.text());
    }

    return response.json();
};

function showSection(id) {
    document.querySelectorAll(".section").forEach(section => {
        section.classList.toggle("active", section.id === id);
    });

    document.querySelectorAll(".nav-item").forEach(button => {
        button.classList.toggle("active", button.dataset.section === id);
    });

    if (id === "incidents") loadIncidents();
    if (id === "memory") loadMemory();
}

document.querySelectorAll(".nav-item").forEach(button => {
    button.addEventListener("click", () => {
        showSection(button.dataset.section);
    });
});

async function loadLearning() {
    try {
        const res = await fetch("/learning");
        const data = await res.json();

        const box = document.getElementById("learning-list");
        if (!box) return;

        if (!data.patterns.length) {
            box.innerHTML = "<p>No learned attack patterns yet.</p>";
            return;
        }

        box.innerHTML = data.patterns.map(item => `
            <div class="learning-item">
                <div class="learning-type">${item.type}</div>
                <div>${item.text}</div>
            </div>
        `).join("");
    } catch (e) {
        console.error(e);
    }
}

async function loadMetrics() {
    try {
        const data = await api("/metrics");

        $("trusted-count").textContent = data.trusted_memories;
        $("review-count").textContent = data.review_items;
        $("quarantine-count").textContent = data.quarantined_memories;
        $("recovered-count").textContent = data.recovered_incidents;
    } catch (error) {
        console.error(error);
    }
}

async function loadIncidents() {
    const container = $("incident-list");

    try {
        const incidents = await api("/incidents/timeline");

        if (!incidents.length) {
            container.innerHTML =
                '<div class="empty-state">No incidents detected.</div>';
            return;
        }

        container.innerHTML = incidents.map(incident => `
            <div class="incident">
                <div>
                    <span class="badge">
                        ${escapeHtml(incident.status.toUpperCase())}
                    </span>

                    <h4>${escapeHtml(incident.title)}</h4>

                    <p>
                        Risk score:
                        <strong>${incident.risk_score}</strong>
                          Source:
                        ${escapeHtml(incident.source)}
                    </p>

                    <p>
                        ${escapeHtml(incident.incident_id)}
                          ${formatDate(incident.created_at)}
                    </p>
                </div>

                <div>
                    <strong>
                        ${escapeHtml(incident.severity.toUpperCase())}
                    </strong>

                    <div class="incident-actions">
                        ${
                            incident.status === "open"
                                ? `<button onclick="quarantineIncident('${incident.incident_id}')">
                                    QUARANTINE
                                   </button>`
                                : ""
                        }

                        ${
                            incident.status === "quarantined"
                                ? `<button onclick="recoverIncident('${incident.incident_id}')">
                                    RECOVER
                                   </button>`
                                : ""
                        }
                    </div>
                </div>
            </div>
        `).join("");

    } catch (error) {
        container.innerHTML =
            '<div class="empty-state">Unable to load incidents.</div>';

        console.error(error);
    }
}

async function quarantineIncident(id) {
    try {
        await api(`/incidents/${id}/quarantine`, {
            method: "POST"
        });

        await loadIncidents();
        await loadMetrics();

    } catch (error) {
        console.error(error);
        alert("Unable to quarantine incident.");
    }
}

async function recoverIncident(id) {
    try {
        await api(
            `/incidents/${id}/recover?resolution=${encodeURIComponent(
                "Malicious memory removed from trusted context"
            )}`,
            {
                method: "POST"
            }
        );

        await loadIncidents();
        await loadMetrics();

    } catch (error) {
        console.error(error);
        alert("Unable to recover incident.");
    }
}

async function loadMemory() {
    const container = $("memory-list");

    try {
        const memories = await api("/memory");

        if (!memories.length) {
            container.innerHTML =
                '<div class="empty-state">No trusted memories.</div>';
            return;
        }

        container.innerHTML = memories.map(memory => `
            <div class="memory-item">
                <h4>Trusted Memory</h4>
                <p>${escapeHtml(memory.content)}</p>
                <p>
                    Source: ${escapeHtml(memory.source)}
                      Risk: ${memory.risk_score}
                </p>
            </div>
        `).join("");

    } catch (error) {
        container.innerHTML =
            '<div class="empty-state">Unable to load memory.</div>';

        console.error(error);
    }
}

async function sendChat() {
    const input = $("chat-input");
    const output = $("chat-output");
    const message = input.value.trim();

    if (!message) return;

    output.innerHTML += `
        <div class="chat-message user-message">
            <strong>YOU</strong>
            <p>${escapeHtml(message)}</p>
        </div>
    `;

    input.value = "";

    try {
        const check = await api(
            `/memory/check?content=${encodeURIComponent(message)}&source=user`,
            {
                method: "POST"
            }
        );

        if (check.action !== "allow") {
            const names = check.findings
                .map(item => item.name)
                .join(", ");

            output.innerHTML += `
                <div class="chat-message agent-message blocked-message">
                    <strong>MEMORYSHIELD</strong>

                    <p>
                        MEMORY BLOCKED
                    </p>

                    <small>
                        Risk: ${check.score}
                          Action: ${escapeHtml(check.action.toUpperCase())}
                          Detection: ${escapeHtml(names)}
                    </small>

                    <small>
                        NOT STORED IN TRUSTED MEMORY
                    </small>
                </div>
            `;

            return;
        }

        const data = await api(
            `/agent/chat?message=${encodeURIComponent(message)}`,
            {
                method: "POST"
            }
        );

        output.innerHTML += `
            <div class="chat-message agent-message">
                <strong>MEMORYSHIELD</strong>

                <p>${escapeHtml(data.message || "")}</p>

                <small>
                    ${
                        data.memory_context
                            ? "Protected context loaded from memory."
                            : "No trusted memory context recalled."
                    }
                </small>
            </div>
        `;

    } catch (error) {
        output.innerHTML += `
            <div class="chat-message agent-message blocked-message">
                <strong>MEMORYSHIELD</strong>
                <p>Security check failed.</p>
                <small>Memory was not stored.</small>
            </div>
        `;

        console.error(error);
    }

    output.scrollTop = output.scrollHeight;
}

$("chat-send").addEventListener("click", sendChat);

$("chat-input").addEventListener("keydown", event => {
    if (event.key === "Enter") {
        sendChat();
    }
});

function formatDate(value) {
    if (!value) return "Unknown time";

    return new Date(value).toLocaleString();
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

async function refresh() {
    await loadMetrics();
    await loadLearning();

    const active = document.querySelector(".section.active");

    if (active?.id === "incidents") {
        await loadIncidents();
    }

    if (active?.id === "memory") {
        await loadMemory();
    }
}

refresh();

setInterval(refresh, 5000);
