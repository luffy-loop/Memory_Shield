const $ = (id) => document.getElementById(id);

let activeSection = "overview";

function showSection(id) {
    activeSection = id;

    document.querySelectorAll(".section").forEach(section => {
        section.classList.toggle("active", section.id === id);
    });

    document.querySelectorAll(".nav-item").forEach(item => {
        item.classList.toggle(
            "active",
            item.dataset.section === id
        );
    });

    const chatSend = $("chat-send");
const chatInput = $("chat-input");

if (chatSend) {
    chatSend.addEventListener("click", sendChat);
}

if (chatInput) {
    chatInput.addEventListener("keydown", event => {
        if (event.key === "Enter") {
            event.preventDefault();
            sendChat();
        }
    });
}

    if (id === "agent-security") loadAgentSecurity();
    if (id === "learning") loadLearning();
    if (id === "incidents") loadIncidents();
    if (id === "memory") loadMemory();
}

document.querySelectorAll(".nav-item").forEach(item => {
    item.addEventListener("click", () => {
        showSection(item.dataset.section);
    });
});

async function loadAgentSecurity(){try{const r=await fetch("/agents/summary"),d=await r.json(),s=d.summary||{};if($("agent-actions"))$("agent-actions").textContent=s.total_actions||0;if($("agent-allowed"))$("agent-allowed").textContent=s.allowed||0;if($("agent-blocked"))$("agent-blocked").textContent=s.blocked||0;if($("agent-review"))$("agent-review").textContent=s.review||0;const l=$("agent-list");if(l)l.innerHTML=(d.registry||[]).map(a=>{const x=(d.agents||{})[a.agent_id]||{};return `<div class="agent-row"><div><strong>${escapeHtml(a.name)}</strong><small>${escapeHtml(a.description)}</small><div class="agent-tags">${a.tools.map(t=>`<span>${escapeHtml(t)}</span>`).join("")}</div></div><div class="agent-state"><b>${escapeHtml(a.status).toUpperCase()}</b><small>${x.actions||0} actions · max risk ${x.risk||0}</small></div></div>`}).join("")}catch(e){console.error(e)}try{const r=await fetch("/agents/audit"),e=await r.json(),l=$("agent-audit-list");if(l)l.innerHTML=e.slice(0,12).map(x=>`<div class="audit-row"><div><strong>${escapeHtml(x.agent_id)}</strong> ${escapeHtml(x.tool)}:${escapeHtml(x.action)}</div><div class="audit-decision">${escapeHtml(x.decision).toUpperCase()} · ${x.risk_score}</div><small>${escapeHtml(x.reason)}</small></div>`).join("")}catch(e){console.error(e)}}

async function loadMetrics() {
    try {
        const response = await fetch("/metrics");
        const data = await response.json();

        if ($("trusted-count"))
            $("trusted-count").textContent = data.trusted_memories;

        if ($("review-count"))
            $("review-count").textContent = data.review_items;

        if ($("quarantine-count"))
            $("quarantine-count").textContent = data.quarantined_memories;

        if ($("incident-count"))
            $("incident-count").textContent = data.incidents;

        if ($("open-incidents"))
            $("open-incidents").textContent = data.open_incidents;

        if ($("recovered-count"))
    $("recovered-count").textContent =
        data.recovered_incidents;
    } catch (error) {
        console.error(error);
    }
}

async function loadLearning() {
    const list = $("learning-list");

    if (!list) return;

    try {
        const response = await fetch("/learning");
        const data = await response.json();

        if (!data.patterns || data.patterns.length === 0) {
            list.innerHTML =
                '<div class="empty-state">No learned security patterns yet.</div>';
            return;
        }

        list.innerHTML = data.patterns.map(pattern => `
            <div class="learning-item">
                <div class="learning-type">
                    ${escapeHtml(pattern.type || "learned")}
                </div>
                <div>
                    ${escapeHtml(pattern.text)}
                </div>
            </div>
        `).join("");
    } catch (error) {
        list.innerHTML =
            '<div class="empty-state">Learning data unavailable.</div>';
    }
}

async function loadIncidents() {
    const list = $("incident-list");

    if (!list) return;

    try {
        const response = await fetch("/incidents/timeline");
        const incidents = await response.json();

        if (!incidents.length) {
            list.innerHTML =
                '<div class="empty-state">No security incidents detected.</div>';
            return;
        }

        list.innerHTML = incidents.map(incident => {
            const status = String(incident.status || "open").toUpperCase();
            const severity = String(incident.severity || "unknown").toUpperCase();

            let action = "";

            if (incident.status === "open") {
                action = `
                    <button class="incident-action"
                        onclick="quarantineIncident('${incident.incident_id}')">
                        QUARANTINE
                    </button>
                `;
            } else if (incident.status === "quarantined") {
                action = `
                    <button class="incident-action"
                        onclick="recoverIncident('${incident.incident_id}')">
                        RECOVER
                    </button>
                `;
            } else if (incident.status === "recovered") {
                action = `
                    <div class="incident-resolved">
                        RECOVERED
                    </div>
                `;
            }

            return `
                <article class="incident-card">
                    <div class="incident-main">
                        <div class="incident-status">
                            ${escapeHtml(status)}
                        </div>

                        <h3>
                            ${escapeHtml(incident.title)}
                        </h3>

                        <div class="incident-meta">
                            Risk score:
                            <strong>${incident.risk_score}</strong>
                            Source:
                            ${escapeHtml(incident.source)}
                        </div>

                        <div class="incident-meta">
                            ${escapeHtml(incident.incident_id)}
                            ${formatDate(incident.created_at)}
                        </div>

                        ${
                            incident.resolution
                                ? `
                                <div class="incident-resolution">
                                    ${escapeHtml(incident.resolution)}
                                </div>
                                `
                                : ""
                        }
                    </div>

                    <div class="incident-side">
                        <div class="incident-severity">
                            ${escapeHtml(severity)}
                        </div>
                        ${action}
                    </div>
                </article>
            `;
        }).join("");
    } catch (error) {
        list.innerHTML =
            '<div class="empty-state">Unable to load incidents.</div>';
        console.error(error);
    }
}

async function quarantineIncident(id) {
    try {
        const response = await fetch(
            `/incidents/${encodeURIComponent(id)}/quarantine`,
            {
                method: "POST"
            }
        );

        if (!response.ok) {
            throw new Error("Quarantine failed");
        }

        await refresh();
    } catch (error) {
        console.error(error);
        alert("Unable to quarantine incident.");
    }
}

async function recoverIncident(id) {
    const resolution =
        "Malicious memory removed from trusted context";

    try {
        const response = await fetch(
            `/incidents/${encodeURIComponent(id)}/recover?resolution=${encodeURIComponent(resolution)}`,
            {
                method: "POST"
            }
        );

        if (!response.ok) {
            throw new Error("Recovery failed");
        }

        await refresh();
    } catch (error) {
        console.error(error);
        alert("Unable to recover incident.");
    }
}

async function loadMemory() {
    const list = $("memory-list");

    if (!list) return;

    try {
        const response = await fetch("/memory");
        const memories = await response.json();

        if (!memories.length) {
            list.innerHTML =
                '<div class="empty-state">No trusted memories yet.</div>';
            return;
        }

        list.innerHTML = memories.map(memory => `
            <div class="memory-item">
                <div class="memory-content">
                    ${escapeHtml(memory.content)}
                </div>

                <div class="memory-meta">
                    Source:
                    ${escapeHtml(memory.source)}
                    · Risk:
                    ${memory.risk_score}
                </div>
            </div>
        `).join("");
    } catch (error) {
        list.innerHTML =
            '<div class="empty-state">Unable to load memory.</div>';
        console.error(error);
    }
}

async function sendChat() {
    const input = $("chat-input");

    if (!input) return;

    const message = input.value.trim();

    if (!message) return;

    const resultBox = $("chat-result");

    if (resultBox) {
        resultBox.innerHTML =
            '<div class="empty-state">Analyzing memory request...</div>';
    }

    try {
        const params = new URLSearchParams();
        params.set("message", message);

        const response = await fetch(
            `/agent/chat?${params.toString()}`,
            {
                method: "POST"
            }
        );

        if (!response.ok) {
            throw new Error("Agent request failed");
        }

        const data = await response.json();

        renderSecurityResult(data);

        input.value = "";

        await refresh();
    } catch (error) {
        console.error(error);

        if (resultBox) {
            resultBox.innerHTML =
                '<div class="empty-state">Agent request failed.</div>';
        }
    }
}

function renderSecurityResult(data) {
    const box = $("chat-result");

    if (!box) return;

    const security = data.security || {};
    const findings = security.findings || [];

    const actionRaw = String(
    security.action || "unknown"
).toLowerCase();

const action = actionRaw.toUpperCase();
const score = Number(security.score || 0);

const blocked = actionRaw === "quarantine";
const review = actionRaw === "review";

const statusClass = blocked
    ? "security-blocked"
    : review
        ? "security-review"
        : "security-allowed";

const decisionTitle = blocked
    ? "MEMORY WRITE BLOCKED"
    : review
        ? "MEMORY REQUIRES REVIEW"
        : "MEMORY ACCEPTED";

    const findingsHtml = findings.length
        ? findings.map(item => `
            <div class="security-finding">
                <span>${escapeHtml(item.name)}</span>
                <strong>${item.score}</strong>
            </div>
        `).join("")
        : `
            <div class="security-finding">
                <span>No suspicious signals detected</span>
                <strong>0</strong>
            </div>
        `;

    box.innerHTML = `
        <div class="security-result ${statusClass}">
            <div class="security-result-header">
                <div>
                    <div class="security-label">
                        SECURITY DECISION
                    </div>

                    <h3>${decisionTitle}</h3>
                </div>

                <div class="security-score">
                    <span>RISK</span>
                    <strong>${score}</strong>
                </div>
            </div>

            <div class="security-action">
                <span>ACTION</span>
                <strong>${escapeHtml(action)}</strong>
            </div>

            <div class="security-divider"></div>

            <div class="security-label">
                DETECTIONS
            </div>

            <div class="security-findings">
                ${findingsHtml}
            </div>

            <div class="security-divider"></div>

            <div class="security-message">
                ${escapeHtml(data.response || "")}
            </div>
        </div>
    `;
}

function formatDate(value) {
    if (!value) return "";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return "";
    }

    return date.toLocaleString();
}

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

async function refresh() {
    await loadMetrics();

    if (activeSection === "incidents") {
        await loadIncidents();
    }

    if (activeSection === "memory") {
        await loadMemory();
    }

    if (activeSection === "agent-security") await loadAgentSecurity();

    if (activeSection === "learning") {
        await loadLearning();
    }
}

refresh();

setInterval(refresh, 5000);