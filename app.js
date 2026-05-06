const eventsTable = document.getElementById("eventsTable");
const reasoningContent = document.getElementById("reasoningContent");
const backendStatus = document.getElementById("backendStatus");
const simResult = document.getElementById("simResult");
const replayBtn = document.getElementById("replayBtn");
const riskCards = document.getElementById("riskCards");
const sidebarNav = document.getElementById("sidebarNav");
const alertsContent = document.getElementById("alertsContent");
const reportsContent = document.getElementById("reportsContent");
const dangerousIpHighlight = document.getElementById("dangerousIpHighlight");
const networkBg = document.getElementById("networkBg");

const EVENT_WINDOW_LIMIT = 20;
const REFRESH_INTERVAL_MS = 2500;
const FLOW_STAGES = ["Monitoring", "Suspicious", "Attack", "Blocked"];

const RISK_THRESHOLDS = {
  medium: 45,
  high: 75,
  alert: 70,
};

const GEO_LOOKUP = [
  { country: "US", flag: "🇺🇸" },
  { country: "DE", flag: "🇩🇪" },
  { country: "IN", flag: "🇮🇳" },
  { country: "JP", flag: "🇯🇵" },
  { country: "SG", flag: "🇸🇬" },
  { country: "BR", flag: "🇧🇷" },
  { country: "GB", flag: "🇬🇧" },
  { country: "AU", flag: "🇦🇺" },
];

const VIEW_MAP = {
  dashboard: [
    "riskCards",
    "controlsPanel",
    "incidentsPanel",
    "analystPanel",
    "feedPanel",
    "storyPanel",
    "timelinePanel",
    "alertsPanel",
    "reportsPanel",
  ],
  incidents: ["incidentsPanel"],
  alerts: ["alertsPanel"],
  liveTraffic: ["feedPanel"],
  aiAnalyst: ["analystPanel"],
  timeline: ["timelinePanel", "storyPanel"],
  reports: ["reportsPanel"],
};

const state = {
  events: [],
  summary: null,
  lastEventId: null,
  lastSummarySignature: "",
  lastEventsSignature: "",
  refreshTimer: null,
  isUpdating: false,
  replayTimers: [],
  backgroundFrame: null,
};

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function geoForIp(ip) {
  let hash = 0;
  const safeIp = ip || "0.0.0.0";
  for (let i = 0; i < safeIp.length; i += 1) hash = (hash * 31 + safeIp.charCodeAt(i)) >>> 0;
  return GEO_LOOKUP[hash % GEO_LOOKUP.length];
}

function severityByRisk(score) {
  if (score >= RISK_THRESHOLDS.high) return "HIGH";
  if (score >= RISK_THRESHOLDS.medium) return "MEDIUM";
  return "LOW";
}

function severityClass(level) {
  if (level === "HIGH") return "high";
  if (level === "MEDIUM") return "medium";
  return "low";
}

function decisionClass(decision) {
  switch (decision) {
    case "MONITOR":
      return "monitor";
    case "RATE_LIMIT":
      return "rate_limit";
    case "BLOCK":
      return "block";
    default:
      return "allow";
  }
}

function normalizeStage(stage) {
  if (!stage || stage === "Normal") return "Monitoring";
  return stage;
}

function getCanvasDpr() {
  return Math.min(1.5, window.devicePixelRatio || 1);
}

function createAiNarrativeBlock(event) {
  const ai = event?.ai_analysis;
  if (ai) {
    return `
      <p><strong>Explanation:</strong> ${escapeHtml(ai.explanation || "N/A")}</p>
      <p><strong>Threat Assessment:</strong> ${escapeHtml(ai.threat_assessment || "N/A")}</p>
      <p><strong>Decision Justification:</strong> ${escapeHtml(ai.decision_justification || "N/A")}</p>
      <p><strong>Recommendation:</strong> ${escapeHtml(ai.recommendation || "N/A")}</p>
    `;
  }
  return `<p><strong>AI Explanation:</strong> ${escapeHtml(humanNarrative(event))}</p>`;
}

async function fetchJSON(url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed: ${response.status}`);
  }
  return response.json();
}

function switchView(view) {
  const allowed = new Set(VIEW_MAP[view] || VIEW_MAP.dashboard);
  document.querySelectorAll(".view-panel").forEach((panel) => {
    panel.classList.toggle("view-hidden", !allowed.has(panel.id));
  });
  sidebarNav?.querySelectorAll(".nav-link").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === view);
  });
}

function renderRiskCards(summary) {
  const attackSummary = summary.attack_summary || {};
  const cards = [
    { label: "Total Requests", value: summary.total_requests ?? 0 },
    { label: "Average Risk", value: Number(summary.avg_risk_score ?? 0).toFixed(2) },
    { label: "Blocked IPs", value: (summary.blocked_ips || []).length },
    { label: "Top Threat Type", value: attackSummary.top_threat_type || "No active threat" },
  ];

  riskCards.innerHTML = cards
    .map(
      (card) => `
      <article class="panel metric-card">
        <span>${escapeHtml(card.label)}</span>
        <strong>${escapeHtml(card.value)}</strong>
      </article>`
    )
    .join("");
}

function renderIncidents(incidents) {
  const container = document.getElementById("incidentList");
  if (!incidents.length) {
    container.innerHTML = `<p class="muted">No active incidents.</p>`;
    return;
  }

  container.innerHTML = incidents
    .slice(0, 10)
    .map((incident, index) => {
      const risk = Number(incident.latest_risk ?? incident.latest_risk_score ?? 0);
      const level = severityByRisk(risk);
      const geo = geoForIp(incident.ip_address);
      const stage = normalizeStage(incident.latest_stage);
      const lastActivity = incident.last_activity
        ? new Date(incident.last_activity).toLocaleTimeString()
        : "N/A";
      return `
        <div class="incident-card ${index === 0 ? "top-risk" : ""}">
          <div class="incident-head">
            <strong>${escapeHtml(incident.ip_address || "Unknown IP")}</strong>
            <span class="badge ${severityClass(level)}">${escapeHtml(level)}</span>
          </div>
          <p class="muted">Country: ${geo.flag} ${geo.country}</p>
          <p class="muted">Threat: ${escapeHtml(incident.attack_type || "Normal")}</p>
          <p class="muted">Status: ${escapeHtml(incident.status || "Monitoring")}</p>
          <p class="muted">Stage: ${escapeHtml(stage)}</p>
          <p class="muted">Last activity: ${escapeHtml(lastActivity)}</p>
        </div>
      `;
    })
    .join("");
}

function humanNarrative(event) {
  const defaultNarrative =
    "This request matches known SQL injection patterns and significantly deviates from normal traffic behavior. Immediate rate limiting is recommended.";
  if (!event) return defaultNarrative;

  if (event.analyst_narrative) {
    return event.analyst_narrative;
  }

  const findings = event.analysis?.findings || [];
  const reasons = event.analysis?.reasons || [];
  const attackType = event.attack_type || "suspicious behavior";
  const decision = event.decision || "MONITOR";
  const reason = reasons[0] || "it deviates from normal traffic behavior";

  return `This request matches ${attackType} indicators and ${reason.toLowerCase()}. ${decision} is recommended immediately.`;
}

function renderReasoning(event) {
  if (!event) {
    reasoningContent.innerHTML = `<p class="muted">No events yet. Generate traffic to see analysis.</p>`;
    return;
  }

  const findings = (event.analysis?.findings || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  const reasons = (event.analysis?.reasons || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("");

  reasoningContent.innerHTML = `
    ${createAiNarrativeBlock(event)}
    <p><strong>Action:</strong> <span class="${decisionClass(event.decision)}">${escapeHtml(event.decision || "ALLOW")}</span></p>
    <p><strong>Risk Score:</strong> ${escapeHtml(Number(event.risk_score || 0).toFixed(2))}/100</p>
    <p><strong>Findings:</strong></p>
    <ul>${findings || "<li>No findings</li>"}</ul>
    <p><strong>Reasons:</strong></p>
    <ul>${reasons || "<li>No reasons</li>"}</ul>
  `;
}

function renderAttackFlow(stage) {
  const target = normalizeStage(stage);
  const activeIndex = Math.max(0, FLOW_STAGES.indexOf(target));
  const flow = document.getElementById("attackFlow");

  const flowClassForIndex = (index) => {
    if (index < activeIndex) return "reached";
    if (index === activeIndex) return "active";
    return "";
  };

  flow.innerHTML = FLOW_STAGES.map((item, index) => {
    const cls = flowClassForIndex(index);
    return `<div class="flow-node ${cls}">${item}</div>`;
  }).join("");
}

function storyStepsFromEvent(event) {
  if (!event) {
    return [];
  }

  if (Array.isArray(event.story_steps) && event.story_steps.length) {
    return event.story_steps.map((step) => ({
      title: step.title,
      detail: step.detail,
    }));
  }

  return [
    { title: "Request received", detail: `Traffic arrived from ${event.request?.ip_address || "unknown source"}.` },
    { title: "Suspicious pattern detected", detail: "Rule-based and anomaly checks flagged unusual behavior." },
    { title: "Risk score increased", detail: `Risk moved to ${Number(event.risk_score || 0).toFixed(2)}.` },
    { title: "AI reasoning applied", detail: humanNarrative(event) },
    { title: "Action taken", detail: `System executed ${event.decision || "MONITOR"}.` },
  ];
}

function renderStory(event) {
  const container = document.getElementById("storyTimeline");
  const steps = storyStepsFromEvent(event);
  if (!steps.length) {
    container.innerHTML = `<p class="muted">No attack story available yet.</p>`;
    return;
  }

  container.innerHTML = steps
    .map(
      (step, index) => `
      <div class="story-step" data-step-index="${index}">
        <h4>Step ${index + 1}: ${escapeHtml(step.title || "Event")}</h4>
        <p>${escapeHtml(step.detail || "")}</p>
      </div>`
    )
    .join("");
}

function replayStory() {
  const steps = Array.from(document.querySelectorAll("#storyTimeline .story-step"));
  state.replayTimers.forEach((timer) => clearTimeout(timer));
  state.replayTimers = [];

  steps.forEach((element) => element.classList.remove("active"));

  steps.forEach((element, index) => {
    const timer = setTimeout(() => {
      steps.forEach((item) => item.classList.remove("active"));
      element.classList.add("active");
    }, index * 1000);
    state.replayTimers.push(timer);
  });
}

function renderEvents(events) {
  state.events = events.slice(0, EVENT_WINDOW_LIMIT);
  const latestEventId = state.events[0]?.id;
  const newEventIds = new Set();
  if (state.lastEventId) {
    for (const event of state.events) {
      if (event.id === state.lastEventId) break;
      newEventIds.add(event.id);
    }
  }

  const rows = state.events
    .map((event) => {
      const date = new Date(event.timestamp).toLocaleTimeString();
      const ip = event.request?.ip_address || "-";
      const geo = geoForIp(ip);
      const level = severityByRisk(Number(event.risk_score || 0));
      const isNew = newEventIds.has(event.id);
      const riskRowClass = level === "HIGH" ? "risk-high" : level === "MEDIUM" ? "risk-medium" : "";

      return `
      <tr class="${[isNew ? "new-row" : "", riskRowClass].filter(Boolean).join(" ")}">
        <td>${escapeHtml(date)}</td>
        <td>${escapeHtml(ip)}</td>
        <td>${geo.flag} ${geo.country}</td>
        <td>${escapeHtml(event.request?.url || "-")}</td>
        <td><span class="badge ${severityClass(level)}">${escapeHtml(Number(event.risk_score || 0).toFixed(2))}</span></td>
        <td><span class="${decisionClass(event.decision)}">${escapeHtml(event.decision || "ALLOW")}</span></td>
      </tr>`;
    })
    .join("");

  eventsTable.innerHTML = rows || `<tr><td colspan="6" class="muted">No traffic yet.</td></tr>`;

  const latest = state.events[0];
  renderReasoning(latest);
  renderStory(latest);
  renderAttackFlow(latest?.timeline_stage || "Monitoring");

  if (latestEventId) state.lastEventId = latestEventId;
}

function renderAlertsAndReports(summary, events) {
  const latest = events[0];
  const blocked = Number(summary?.decisions?.BLOCK || 0);
  const monitored = Number(summary?.decisions?.MONITOR || 0);

  alertsContent.innerHTML = `
    <p><strong>Blocked Decisions:</strong> ${escapeHtml(blocked)}</p>
    <p><strong>Monitor Decisions:</strong> ${escapeHtml(monitored)}</p>
    <p><strong>Most Dangerous IP:</strong> ${escapeHtml(summary?.attack_summary?.most_dangerous_ip || "N/A")}</p>
  `;

  reportsContent.innerHTML = `
    <p><strong>Total Requests:</strong> ${escapeHtml(summary?.total_requests ?? 0)}</p>
    <p><strong>Average Risk:</strong> ${escapeHtml(Number(summary?.avg_risk_score || 0).toFixed(2))}</p>
    <p><strong>Latest Action:</strong> ${escapeHtml(latest?.decision || "ALLOW")}</p>
  `;
}

function updateSummaryUI(summary) {
  state.summary = summary;
  renderRiskCards(summary);
  renderIncidents(summary.incidents || []);
  dangerousIpHighlight.textContent = `Top IP: ${summary?.attack_summary?.most_dangerous_ip || "N/A"}`;
}

function summarySignature(summary) {
  return [
    summary.total_requests,
    summary.avg_risk_score,
    summary.decisions?.ALLOW,
    summary.decisions?.MONITOR,
    summary.decisions?.RATE_LIMIT,
    summary.decisions?.BLOCK,
    summary.attack_summary?.most_dangerous_ip,
  ].join("|");
}

function eventsSignature(events) {
  return events.slice(0, 5).map((event) => event.id).join("|");
}

async function refresh() {
  if (state.isUpdating) return;
  state.isUpdating = true;

  try {
    const [summary, eventsPayload] = await Promise.all([
      fetchJSON("/api/summary"),
      fetchJSON(`/api/events?limit=${EVENT_WINDOW_LIMIT}`),
    ]);

    backendStatus.textContent = "Backend Online";

    const events = (eventsPayload.events || []).slice(0, EVENT_WINDOW_LIMIT);
    const nextSummarySignature = summarySignature(summary);
    const nextEventsSignature = eventsSignature(events);

    const summaryChanged = nextSummarySignature !== state.lastSummarySignature;
    const eventsChanged = nextEventsSignature !== state.lastEventsSignature;

    if (summaryChanged) {
      updateSummaryUI(summary);
      state.lastSummarySignature = nextSummarySignature;
    }

    if (eventsChanged) {
      renderEvents(events);
      renderAlertsAndReports(summary, events);
      state.lastEventsSignature = nextEventsSignature;
    }
  } catch (error) {
    backendStatus.textContent = "Backend Error";
    simResult.textContent = `Error: ${error.message}`;
  } finally {
    state.isUpdating = false;
  }
}

async function runSimulation(scenario, count) {
  const buttons = document.querySelectorAll("button[data-scenario]");
  buttons.forEach((button) => {
    button.disabled = true;
  });

  try {
    const payload = await fetchJSON(`/api/simulate/${scenario}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ count }),
    });

    simResult.textContent = `Generated ${payload.generated_count} ${payload.scenario} event(s).`;
    await refresh();
  } catch (error) {
    simResult.textContent = `Simulation failed: ${error.message}`;
  } finally {
    buttons.forEach((button) => {
      button.disabled = false;
    });
  }
}

function startAutoRefresh() {
  if (state.refreshTimer) {
    clearInterval(state.refreshTimer);
  }
  state.refreshTimer = setInterval(() => {
    if (!state.isUpdating) refresh();
  }, REFRESH_INTERVAL_MS);
}

function initNetworkBackground() {
  if (!networkBg) return;
  const ctx = networkBg.getContext("2d");
  if (!ctx) return;

  const particleCount = 50;
  const particles = [];
  const pointer = { x: 0, y: 0, active: false };
  const maxDistance = 120;

  const resize = () => {
    const dpr = getCanvasDpr();
    const width = Math.max(1, Math.floor(window.innerWidth * dpr));
    const height = Math.max(1, Math.floor(window.innerHeight * dpr));
    networkBg.width = width;
    networkBg.height = height;
    networkBg.style.width = `${window.innerWidth}px`;
    networkBg.style.height = `${window.innerHeight}px`;
    if (!particles.length) {
      for (let i = 0; i < particleCount; i += 1) {
        particles.push({
          x: Math.random() * width,
          y: Math.random() * height,
          vx: (Math.random() - 0.5) * 0.35,
          vy: (Math.random() - 0.5) * 0.35,
          size: 1 + Math.random() * 1.7,
        });
      }
    }
  };

  const draw = () => {
    const width = networkBg.width;
    const height = networkBg.height;
    ctx.clearRect(0, 0, width, height);

    for (const p of particles) {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x <= 0 || p.x >= width) p.vx *= -1;
      if (p.y <= 0 || p.y >= height) p.vy *= -1;

      if (pointer.active) {
        const dx = pointer.x - p.x;
        const dy = pointer.y - p.y;
        const dist = Math.max(1, Math.sqrt(dx * dx + dy * dy));
        if (dist < 160) {
          p.x += (dx / dist) * 0.3;
          p.y += (dy / dist) * 0.3;
        }
      }
    }

    for (let i = 0; i < particles.length; i += 1) {
      for (let j = i + 1; j < particles.length; j += 1) {
        const a = particles[i];
        const b = particles[j];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < maxDistance) {
          ctx.strokeStyle = `rgba(56, 189, 248, ${(1 - dist / maxDistance) * 0.14})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
    }

    for (const p of particles) {
      ctx.fillStyle = "rgba(99, 102, 241, 0.2)";
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
      ctx.fill();
    }

    state.backgroundFrame = requestAnimationFrame(draw);
  };

  window.addEventListener("pointermove", (event) => {
    const dpr = getCanvasDpr();
    pointer.x = event.clientX * dpr;
    pointer.y = event.clientY * dpr;
    pointer.active = true;
  });
  window.addEventListener("pointerleave", () => {
    pointer.active = false;
  });
  window.addEventListener("resize", resize);
  resize();
  draw();
}

function boot() {
  switchView("dashboard");
  renderAttackFlow("Monitoring");
  initNetworkBackground();
  refresh();
  startAutoRefresh();

  document.querySelectorAll("button[data-scenario]").forEach((button) => {
    button.addEventListener("click", async () => {
      const scenario = button.getAttribute("data-scenario");
      const count = Number(document.getElementById("simulateCount").value || 1);
      await runSimulation(scenario, Math.max(1, Math.min(200, count)));
    });
  });

  replayBtn?.addEventListener("click", replayStory);

  sidebarNav?.querySelectorAll(".nav-link").forEach((button) => {
    button.addEventListener("click", () => switchView(button.dataset.view || "dashboard"));
  });

  window.addEventListener("beforeunload", () => {
    if (state.refreshTimer) {
      clearInterval(state.refreshTimer);
    }
    if (state.backgroundFrame) {
      cancelAnimationFrame(state.backgroundFrame);
    }
    state.replayTimers.forEach((timer) => clearTimeout(timer));
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", boot, { once: true });
} else {
  boot();
}
