from __future__ import annotations

from collections import Counter, OrderedDict, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import random
import re
import threading
import time
from urllib import request as urllib_request
from urllib.parse import urlparse
import uuid

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest

    SKLEARN_AVAILABLE = True
except Exception:
    SKLEARN_AVAILABLE = False


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
VALID_SCENARIOS = {"normal", "sqli", "xss", "ddos", "anomaly"}
# Keep in sync with frontend EVENT_WINDOW_LIMIT in static/app.js.
EVENT_WINDOW_LIMIT = 20
ANOMALY_PAYLOAD_LENGTH = 220
AI_TRIGGER_RISK = 50.0
SUMMARY_CACHE_TTL_SECONDS = 1.5


class RequestInput(BaseModel):
    ip_address: str = Field(..., min_length=3, max_length=64)
    method: str = Field(default="GET", min_length=3, max_length=10)
    url: str = Field(default="/", min_length=1, max_length=300)
    payload_text: str = Field(default="", max_length=5000)
    form_input: str = Field(default="", max_length=3000)
    user_agent: str = Field(default="Unknown", max_length=300)


class SimulateRequest(BaseModel):
    count: int = Field(default=1, ge=1, le=200)


@dataclass
class AnomalyResult:
    detected: bool
    score: float
    reason: str


class ThreatEngine:
    SQLI_PATTERNS = [
        re.compile(r"\bUNION\b", re.IGNORECASE),
        re.compile(r"\bSELECT\b.*\bFROM\b", re.IGNORECASE),
        re.compile(r"\bOR\b\s+1\s*=\s*1", re.IGNORECASE),
        re.compile(r"\bDROP\b\s+TABLE\b", re.IGNORECASE),
        re.compile(r"(--|#|/\*)", re.IGNORECASE),
    ]
    XSS_PATTERNS = [
        re.compile(r"<\s*script\b", re.IGNORECASE),
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"onerror\s*=", re.IGNORECASE),
        re.compile(r"onload\s*=", re.IGNORECASE),
        re.compile(r"<\s*img\b[^>]*on\w+\s*=", re.IGNORECASE),
    ]

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.events: list[dict] = []
        self.blocked_ips: set[str] = set()
        self.recent_per_ip: defaultdict[str, deque[float]] = defaultdict(deque)
        self.window_seconds = 10
        self.ddos_threshold = 20
        self.max_events = 100
        self.max_tracked_ips = 2000
        self.maintenance_interval = 25
        self._maintenance_counter = 0
        self._event_version = 0
        self._summary_cache: dict | None = None
        self._summary_cache_version = -1
        self._summary_cache_at = 0.0
        self._ai_cache: OrderedDict[str, dict] = OrderedDict()
        self.model = self._init_model()

    def _init_model(self):
        if not SKLEARN_AVAILABLE:
            return None

        rng = np.random.RandomState(42)
        lengths = rng.normal(loc=80, scale=25, size=500).clip(10, 400)
        specials = rng.normal(loc=6, scale=3, size=500).clip(0, 40)
        url_depth = rng.normal(loc=2, scale=1, size=500).clip(1, 8)
        query_tokens = rng.normal(loc=2, scale=1, size=500).clip(0, 10)
        velocity = rng.normal(loc=1.2, scale=0.6, size=500).clip(0, 6)
        training_data = np.column_stack([lengths, specials, url_depth, query_tokens, velocity])

        model = IsolationForest(contamination=0.08, random_state=42, n_estimators=150, n_jobs=1)
        model.fit(training_data)
        return model

    @staticmethod
    def _utc_now() -> datetime:
        return datetime.now(timezone.utc)

    def _extract_features(self, request: RequestInput, request_velocity: float) -> list[float]:
        combined = f"{request.payload_text} {request.form_input}".strip()
        total_length = len(request.url) + len(combined)
        special_count = sum(1 for ch in combined if not ch.isalnum() and not ch.isspace())
        url_depth = request.url.count("/") + 1
        query_tokens = request.url.count("&") + request.url.count("=")
        return [
            float(total_length),
            float(special_count),
            float(url_depth),
            float(query_tokens),
            float(request_velocity),
        ]

    @staticmethod
    def _sanitize_text(value: str, max_len: int) -> str:
        cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", value or "")
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        return cleaned[:max_len]

    def _sanitize_request(self, request: RequestInput) -> RequestInput:
        safe_ip = self._sanitize_text(request.ip_address, 64)
        safe_method = self._sanitize_text(request.method, 10).upper() or "GET"
        safe_url = self._sanitize_text(request.url, 300) or "/"
        safe_payload = self._sanitize_text(request.payload_text, 5000)
        safe_form = self._sanitize_text(request.form_input, 3000)
        safe_ua = self._sanitize_text(request.user_agent, 300) or "Unknown"
        return RequestInput(
            ip_address=safe_ip,
            method=safe_method,
            url=safe_url,
            payload_text=safe_payload,
            form_input=safe_form,
            user_agent=safe_ua,
        )

    @staticmethod
    def _safe_event_for_ai(event_data: dict) -> dict:
        request_data = event_data.get("request", {})
        analysis = event_data.get("analysis", {})
        return {
            "request": {
                "ip_address": request_data.get("ip_address"),
                "method": request_data.get("method"),
                "url": request_data.get("url"),
                "request_length": request_data.get("request_length"),
                "request_velocity_per_sec": request_data.get("request_velocity_per_sec"),
            },
            "analysis": {
                "findings": analysis.get("findings", []),
                "reasons": analysis.get("reasons", []),
                "anomaly_score": analysis.get("anomaly_score"),
            },
            "risk_score": event_data.get("risk_score"),
            "decision": event_data.get("decision"),
            "attack_type": event_data.get("attack_type"),
            "priority_level": event_data.get("priority_level"),
        }

    @staticmethod
    def _is_allowed_ai_endpoint(endpoint: str) -> bool:
        parsed = urlparse(endpoint)
        if parsed.scheme != "https" or not parsed.netloc:
            return False

        allow_hosts = [item.strip().lower() for item in os.getenv("AI_ANALYST_ALLOWED_HOSTS", "").split(",")]
        allow_hosts = [host for host in allow_hosts if host]
        if not allow_hosts:
            return False

        host = parsed.hostname.lower() if parsed.hostname else ""
        return any(host == allowed or host.endswith(f".{allowed}") for allowed in allow_hosts)

    def analyze_with_ai(self, event_data: dict) -> dict:
        payload = self._safe_event_for_ai(event_data)
        cache_key = json.dumps(payload, sort_keys=True)
        if cache_key in self._ai_cache:
            self._ai_cache.move_to_end(cache_key)
            return self._ai_cache[cache_key]

        prompt_template = (
            "You are a professional cybersecurity analyst. Analyze incoming requests, "
            "detect threats, explain clearly, and justify decisions."
        )

        findings = payload["analysis"]["findings"]
        reasons = payload["analysis"]["reasons"]
        risk = float(payload.get("risk_score") or 0.0)
        decision = payload.get("decision") or "MONITOR"
        attack_type = payload.get("attack_type") or "Suspicious activity"
        anomaly_score = float(payload["analysis"].get("anomaly_score") or 0.0)
        anomaly_detected = any("Anomaly" in item for item in findings) or anomaly_score >= 55

        fallback = {
            "explanation": (
                f"This request matches {attack_type.lower()} indicators and deviates from baseline traffic behavior. "
                f"Observed signals include: {', '.join(findings[:3]) or 'no explicit signatures'}."
            ),
            "threat_assessment": (
                f"Risk score is {round(risk, 2)} with anomaly score {round(anomaly_score, 2)}. "
                f"Threat posture is {payload.get('priority_level', 'MEDIUM')}."
            ),
            "decision_justification": (
                f"The recommended action is {decision} because {reasons[0] if reasons else 'the request exhibits suspicious patterns'}."
            ),
            "recommendation": (
                "Apply temporary rate controls, continue monitoring related IP activity, and escalate if repetition continues."
                if decision in {"RATE_LIMIT", "BLOCK", "MONITOR"}
                else "Allow traffic and continue passive monitoring."
            ),
            "model": "hybrid-fallback",
            "prompt_template": prompt_template,
        }

        api_key = os.getenv("AI_ANALYST_API_KEY", "").strip()
        endpoint = os.getenv("AI_ANALYST_ENDPOINT", "").strip()
        if not api_key or not endpoint or not self._is_allowed_ai_endpoint(endpoint):
            self._ai_cache[cache_key] = fallback
            self._ai_cache.move_to_end(cache_key)
            if len(self._ai_cache) > 500:
                self._ai_cache.popitem(last=False)
            return fallback

        try:
            req_payload = {
                "prompt": prompt_template,
                "event": payload,
                "format": ["explanation", "threat_assessment", "decision_justification", "recommendation"],
            }
            body = json.dumps(req_payload).encode("utf-8")
            req = urllib_request.Request(
                endpoint,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}",
                },
                method="POST",
            )
            with urllib_request.urlopen(req, timeout=2.5) as response:
                raw = response.read().decode("utf-8")
            parsed = json.loads(raw)
            ai_result = {
                "explanation": str(parsed.get("explanation") or fallback["explanation"]),
                "threat_assessment": str(
                    parsed.get("threat_assessment") or fallback["threat_assessment"]
                ),
                "decision_justification": str(
                    parsed.get("decision_justification") or fallback["decision_justification"]
                ),
                "recommendation": str(parsed.get("recommendation") or fallback["recommendation"]),
                "model": str(parsed.get("model") or "hybrid-llm"),
                "prompt_template": prompt_template,
            }
            self._ai_cache[cache_key] = ai_result
            self._ai_cache.move_to_end(cache_key)
            if len(self._ai_cache) > 500:
                self._ai_cache.popitem(last=False)
            return ai_result
        except Exception:
            self._ai_cache[cache_key] = fallback
            self._ai_cache.move_to_end(cache_key)
            if len(self._ai_cache) > 500:
                self._ai_cache.popitem(last=False)
            return fallback

    def _detect_anomaly(self, features: list[float]) -> AnomalyResult:
        length, special_count, _, _, velocity = features
        if self.model is not None:
            score = -float(self.model.decision_function([features])[0])
            scaled = max(0.0, min(100.0, (score + 0.25) * 200))
            prediction = int(self.model.predict([features])[0])
            detected = prediction == -1 and scaled >= 55
            reason = (
                "Isolation Forest flagged this request as an outlier."
                if detected
                else "Behavior is within normal baseline."
            )
            return AnomalyResult(detected=detected, score=round(scaled, 2), reason=reason)

        fallback_score = min(100.0, (length * 0.2) + (special_count * 3.5) + (velocity * 8))
        detected = fallback_score >= 75
        reason = (
            "Fallback anomaly logic detected unusual payload and request velocity."
            if detected
            else "Fallback anomaly logic considers this request normal."
        )
        return AnomalyResult(detected=detected, score=round(fallback_score, 2), reason=reason)

    def _update_velocity(self, ip: str, now_ts: float) -> float:
        bucket = self.recent_per_ip[ip]
        bucket.append(now_ts)
        cutoff = now_ts - self.window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        return len(bucket) / self.window_seconds

    def _prune_velocity_buckets(self, now_ts: float) -> None:
        cutoff = now_ts - self.window_seconds
        stale_ips = [
            ip for ip, bucket in self.recent_per_ip.items() if not bucket or bucket[-1] < cutoff
        ]
        for ip in stale_ips:
            self.recent_per_ip.pop(ip, None)

        if len(self.recent_per_ip) <= self.max_tracked_ips:
            return

        ip_activity = sorted(
            ((ip, bucket[-1]) for ip, bucket in self.recent_per_ip.items() if bucket),
            key=lambda item: item[1],
            reverse=True,
        )
        keep = {ip for ip, _ in ip_activity[: self.max_tracked_ips]}
        drop = [ip for ip in self.recent_per_ip.keys() if ip not in keep]
        for ip in drop:
            self.recent_per_ip.pop(ip, None)

    @staticmethod
    def _incident_id(ip_address: str) -> str:
        return f"INC-{ip_address.replace('.', '-')}"

    @staticmethod
    def _attack_type(findings: list[str]) -> str:
        attack_tags: list[str] = []
        if any("SQL Injection" in item for item in findings):
            attack_tags.append("SQL Injection")
        if any("XSS" in item for item in findings):
            attack_tags.append("XSS")
        if any("DDoS" in item for item in findings):
            attack_tags.append("DDoS")
        if any("Anomaly" in item for item in findings):
            attack_tags.append("Anomaly")
        if not attack_tags:
            return "Normal"
        if len(attack_tags) > 1:
            return "Multi-Vector"
        return attack_tags[0]

    @staticmethod
    def _stage_from_decision(decision: str) -> str:
        return {
            "ALLOW": "Normal",
            "MONITOR": "Suspicious",
            "RATE_LIMIT": "Attack",
            "BLOCK": "Blocked",
        }.get(decision, "Normal")

    @staticmethod
    def _stage_index(stage: str) -> int:
        return {
            "Normal": 0,
            "Suspicious": 1,
            "Attack": 2,
            "Blocked": 3,
        }.get(stage, 0)

    @staticmethod
    def _priority_level(risk: float) -> str:
        if risk >= 75:
            return "HIGH"
        if risk >= 40:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _confidence_level(confidence: float) -> str:
        if confidence >= 0.9:
            return "HIGH"
        if confidence >= 0.75:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _most_common(counter: Counter, default: str) -> str:
        return counter.most_common(1)[0][0] if counter else default

    def _recommendations(self, findings: list[str]) -> list[str]:
        recommendations: list[str] = []
        if any("SQL Injection" in item for item in findings):
            recommendations.extend(
                [
                    "Use parameterized queries and ORM protections.",
                    "Enable strict input validation on all query parameters.",
                ]
            )
        if any("XSS" in item for item in findings):
            recommendations.extend(
                [
                    "Sanitize and encode all user-generated HTML output.",
                    "Add a strict Content Security Policy (CSP).",
                ]
            )
        if any("DDoS" in item for item in findings):
            recommendations.extend(
                [
                    "Apply adaptive per-IP rate limits at edge and API gateway.",
                    "Enable burst control and challenge suspicious clients.",
                ]
            )
        if any("Anomaly" in item for item in findings):
            recommendations.append(
                "Investigate request origin and tune anomaly baseline with new normal traffic."
            )
        if not recommendations:
            recommendations.append("Traffic appears healthy. Continue monitoring.")
        return recommendations

    def _build_story_steps(
        self,
        request: RequestInput,
        findings: list[str],
        reasons: list[str],
        risk: float,
        decision: str,
        analyst_explanation: str,
    ) -> list[dict]:
        indicator = findings[0] if findings else "No direct threat indicators"
        rationale = reasons[0] if reasons else "No malicious signature was matched"
        return [
            {
                "step": 1,
                "title": "Request received",
                "detail": f"Incoming {request.method.upper()} request from {request.ip_address} to {request.url}.",
            },
            {
                "step": 2,
                "title": "Suspicious pattern detected",
                "detail": f"Primary signal: {indicator}. {rationale}",
            },
            {
                "step": 3,
                "title": "Risk score increased",
                "detail": f"Risk score calculated at {round(risk, 2)} with decision threshold for {decision}.",
            },
            {
                "step": 4,
                "title": "AI reasoning applied",
                "detail": analyst_explanation,
            },
            {
                "step": 5,
                "title": "Action taken",
                "detail": f"System executed {decision} and updated incident response state.",
            },
        ]

    def _build_analyst_narrative(
        self,
        attack_type: str,
        anomaly_detected: bool,
        decision: str,
        confidence: float,
        risk: float,
    ) -> str:
        confidence_label = self._confidence_level(confidence)
        if attack_type == "Normal":
            return (
                f"This request aligns with normal traffic behavior. "
                f"Risk remains {round(risk, 2)} and confidence is {confidence_label}."
            )

        anomaly_note = (
            " It also deviates from established behavior baselines."
            if anomaly_detected
            else " Signature rules were the primary trigger."
        )
        return (
            f"This request shows {attack_type} indicators and is classified as {decision}."
            f"{anomaly_note} Confidence: {confidence_label}."
        )

    def inspect(self, request: RequestInput) -> dict:
        request = self._sanitize_request(request)
        now = self._utc_now()
        now_ts = now.timestamp()
        text = f"{request.payload_text} {request.form_input}".strip()
        normalized_text = text.lower()

        with self._lock:
            velocity = self._update_velocity(request.ip_address, now_ts)
            self._maintenance_counter += 1
            if self._maintenance_counter >= self.maintenance_interval:
                self._prune_velocity_buckets(now_ts)
                self._maintenance_counter = 0

            findings: list[str] = []
            reasons: list[str] = []
            confidence_values: list[float] = []
            risk = 0.0

            sql_matches = [p.pattern for p in self.SQLI_PATTERNS if p.search(normalized_text)]
            if sql_matches:
                findings.append("SQL Injection pattern detected")
                reasons.append(f"Matched SQLi indicators: {', '.join(sql_matches)}")
                risk += 55 + (len(sql_matches) * 4)
                confidence_values.append(0.92)

            xss_matches = [p.pattern for p in self.XSS_PATTERNS if p.search(normalized_text)]
            if xss_matches:
                findings.append("XSS pattern detected")
                reasons.append(f"Matched XSS indicators: {', '.join(xss_matches)}")
                risk += 50 + (len(xss_matches) * 4)
                confidence_values.append(0.90)

            requests_in_window = int(velocity * self.window_seconds)
            if requests_in_window >= self.ddos_threshold:
                findings.append("DDoS-like traffic spike detected")
                reasons.append(
                    f"IP sent {requests_in_window} requests in {self.window_seconds}s window."
                )
                risk += 45
                confidence_values.append(0.88)

            features = self._extract_features(request, velocity)
            anomaly = self._detect_anomaly(features)
            if anomaly.detected:
                findings.append("Anomaly detected")
                reasons.append(anomaly.reason)
                risk += 25 + (anomaly.score * 0.15)
                confidence_values.append(0.75)

            if request.ip_address in self.blocked_ips:
                findings.append("Previously blocked IP attempted access")
                reasons.append("This source IP is already in block list.")
                risk = max(risk, 95)
                confidence_values.append(0.98)

            risk = max(0.0, min(100.0, risk))
            if not findings:
                risk = min(25.0, 5.0 + (velocity * 20))

            if risk >= 85:
                decision = "BLOCK"
            elif risk >= 60:
                decision = "RATE_LIMIT"
            elif risk >= 35:
                decision = "MONITOR"
            else:
                decision = "ALLOW"

            if decision == "BLOCK":
                self.blocked_ips.add(request.ip_address)
                action = "Request blocked and source IP added to block list."
            elif decision == "RATE_LIMIT":
                action = "Traffic throttled for this source."
            elif decision == "MONITOR":
                action = "Request allowed but marked for enhanced monitoring."
            else:
                action = "Request allowed."

            confidence = round(min(0.99, max(confidence_values) if confidence_values else 0.60), 2)
            status = "suspicious" if decision != "ALLOW" else "normal"
            recommendations = self._recommendations(findings)
            attack_type = self._attack_type(findings)
            stage = self._stage_from_decision(decision)
            priority = self._priority_level(risk)
            incident_id = self._incident_id(request.ip_address)
            analyst_narrative = self._build_analyst_narrative(
                attack_type=attack_type,
                anomaly_detected=anomaly.detected,
                decision=decision,
                confidence=confidence,
                risk=risk,
            )
            ai_analysis = None
            if risk > AI_TRIGGER_RISK or anomaly.detected:
                ai_analysis = self.analyze_with_ai(
                    {
                        "request": {
                            "ip_address": request.ip_address,
                            "method": request.method.upper(),
                            "url": request.url,
                            "request_length": len(request.url) + len(text),
                            "request_velocity_per_sec": round(velocity, 3),
                        },
                        "analysis": {
                            "findings": findings or ["No direct threat indicators"],
                            "reasons": reasons or ["No malicious pattern matched."],
                            "anomaly_score": anomaly.score,
                        },
                        "risk_score": round(risk, 2),
                        "decision": decision,
                        "attack_type": attack_type,
                        "priority_level": priority,
                    }
                )
                analyst_narrative = ai_analysis["explanation"]

            story_steps = self._build_story_steps(
                request=request,
                findings=findings,
                reasons=reasons,
                risk=risk,
                decision=decision,
                analyst_explanation=analyst_narrative,
            )

            event = {
                "id": str(uuid.uuid4()),
                "timestamp": now.isoformat(),
                "request": {
                    "ip_address": request.ip_address,
                    "method": request.method.upper(),
                    "url": request.url,
                    "payload_text": request.payload_text,
                    "form_input": request.form_input,
                    "user_agent": request.user_agent,
                    "request_length": len(request.url) + len(text),
                    "request_velocity_per_sec": round(velocity, 3),
                },
                "analysis": {
                    "findings": findings or ["No direct threat indicators"],
                    "reasons": reasons or ["No malicious pattern matched."],
                    "anomaly_score": anomaly.score,
                    "feature_vector": {
                        "request_length": features[0],
                        "special_character_count": features[1],
                        "url_depth": features[2],
                        "query_token_count": features[3],
                        "request_velocity_per_sec": features[4],
                    },
                },
                "risk_score": round(risk, 2),
                "confidence": confidence,
                "confidence_level": self._confidence_level(confidence),
                "decision": decision,
                "action": action,
                "recommendations": recommendations,
                "status": status,
                "priority_level": priority,
                "attack_type": attack_type,
                "analyst_narrative": analyst_narrative,
                "ai_analysis": ai_analysis,
                "incident": {
                    "incident_id": incident_id,
                    "ip_address": request.ip_address,
                    "attack_type": attack_type,
                    "status": "Blocked" if request.ip_address in self.blocked_ips else stage,
                },
                "story_steps": story_steps,
                "timeline_flow": ["Normal", "Suspicious", "Attack", "Blocked"],
                "timeline_stage": stage,
                "timeline_index": self._stage_index(stage),
            }

            self.events.append(event)
            if len(self.events) > self.max_events:
                self.events = self.events[-self.max_events :]
            self._event_version += 1
            return event

    def latest_events(self, limit: int = 20) -> list[dict]:
        with self._lock:
            bounded_limit = max(1, min(limit, EVENT_WINDOW_LIMIT))
            latest = list(reversed(self.events[-bounded_limit:]))
            return [self._event_feed_view(event) for event in latest]

    @staticmethod
    def _event_feed_view(event: dict) -> dict:
        request = event.get("request", {})
        analysis = event.get("analysis", {})
        incident = event.get("incident", {})
        return {
            "id": event.get("id"),
            "timestamp": event.get("timestamp"),
            "request": {
                "ip_address": request.get("ip_address"),
                "method": request.get("method"),
                "url": request.get("url"),
            },
            "analysis": {
                "findings": analysis.get("findings", []),
                "reasons": analysis.get("reasons", []),
            },
            "risk_score": event.get("risk_score"),
            "confidence": event.get("confidence"),
            "confidence_level": event.get("confidence_level"),
            "decision": event.get("decision"),
            "priority_level": event.get("priority_level"),
            "attack_type": event.get("attack_type"),
            "analyst_narrative": event.get("analyst_narrative"),
            "ai_analysis": event.get("ai_analysis"),
            "incident": {
                "incident_id": incident.get("incident_id"),
                "ip_address": incident.get("ip_address"),
                "status": incident.get("status"),
            },
            "story_steps": event.get("story_steps", []),
            "timeline_stage": event.get("timeline_stage"),
        }

    def summary(self) -> dict:
        with self._lock:
            now_monotonic = time.monotonic()
            if (
                self._summary_cache is not None
                and self._summary_cache_version == self._event_version
                and (now_monotonic - self._summary_cache_at) <= SUMMARY_CACHE_TTL_SECONDS
            ):
                return self._summary_cache

            decisions = Counter(e["decision"] for e in self.events)
            findings = Counter()
            endpoints = Counter()
            threat_types = Counter()
            incidents: dict[str, dict] = {}

            for event in self.events:
                for item in event["analysis"]["findings"]:
                    findings[item] += 1

                ip = event["request"]["ip_address"]
                endpoint = event["request"]["url"]
                endpoints[endpoint] += 1

                attack_type = event.get("attack_type", "Normal")
                if attack_type != "Normal":
                    threat_types[attack_type] += 1

                if ip not in incidents:
                    incidents[ip] = {
                        "incident_id": self._incident_id(ip),
                        "ip_address": ip,
                        "requests": 0,
                        "blocked": ip in self.blocked_ips,
                        "latest_risk": 0.0,
                        "latest_stage": "Normal",
                        "latest_endpoint": endpoint,
                        "latest_activity": event["timestamp"],
                        "attack_types": Counter(),
                    }

                row = incidents[ip]
                row["requests"] += 1
                row["blocked"] = row["blocked"] or event["decision"] == "BLOCK"
                row["latest_risk"] = max(float(row["latest_risk"]), float(event["risk_score"]))
                row["latest_stage"] = event.get("timeline_stage", row["latest_stage"])
                row["latest_endpoint"] = endpoint
                row["latest_activity"] = event["timestamp"]
                row["attack_types"][attack_type] += 1

            total = len(self.events)
            avg_risk = (
                round(sum(event["risk_score"] for event in self.events) / total, 2) if total else 0.0
            )

            incident_rows: list[dict] = []
            for ip, info in incidents.items():
                attack_types_counter = info["attack_types"]
                attack_type = self._most_common(attack_types_counter, "Normal")
                if attack_type == "Normal" and len(attack_types_counter) > 1:
                    filtered = {k: v for k, v in attack_types_counter.items() if k != "Normal"}
                    if filtered:
                        attack_type = max(filtered, key=lambda key: filtered[key])

                incident_rows.append(
                    {
                        "incident_id": info["incident_id"],
                        "ip_address": ip,
                        "attack_type": attack_type,
                        "requests": info["requests"],
                        "status": "Blocked"
                        if info["blocked"]
                        else "Attack"
                        if info["latest_stage"] in {"Attack", "Blocked"}
                        else "Monitoring",
                        "latest_stage": info["latest_stage"],
                        "latest_risk": round(float(info["latest_risk"]), 2),
                        "latest_endpoint": info["latest_endpoint"],
                        "last_activity": info["latest_activity"],
                    }
                )

            incident_rows.sort(key=lambda item: (item["latest_risk"], item["requests"]), reverse=True)
            most_dangerous = incident_rows[0]["ip_address"] if incident_rows else "N/A"

            result = {
                "total_requests": total,
                "avg_risk_score": avg_risk,
                "blocked_ips": sorted(self.blocked_ips),
                "decisions": {
                    "ALLOW": decisions.get("ALLOW", 0),
                    "MONITOR": decisions.get("MONITOR", 0),
                    "RATE_LIMIT": decisions.get("RATE_LIMIT", 0),
                    "BLOCK": decisions.get("BLOCK", 0),
                },
                "findings": dict(findings),
                "model": "IsolationForest" if self.model is not None else "HeuristicFallback",
                "last_updated": self._utc_now().isoformat(),
                "incidents": incident_rows,
                "active_incidents": sum(1 for row in incident_rows if row["status"] != "Blocked"),
                "attack_summary": {
                    "top_threat_type": self._most_common(threat_types, "No active threat"),
                    "most_attacked_endpoint": self._most_common(endpoints, "N/A"),
                    "most_dangerous_ip": most_dangerous,
                },
            }
            self._summary_cache = result
            self._summary_cache_version = self._event_version
            self._summary_cache_at = now_monotonic
            return result


app = FastAPI(
    title="Cognitive Threat Investigator",
    description="AI-powered real-time cloud security analysis dashboard.",
    version="1.0.0",
)
app.add_middleware(GZipMiddleware, minimum_size=1024)
engine = ThreatEngine()

app.mount("/static", StaticFiles(directory=str(STATIC_DIR), html=False), name="static")


@app.get("/")
async def root() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@app.post("/api/inspect")
async def inspect_request(payload: RequestInput) -> dict:
    return engine.inspect(payload)


@app.get("/api/events")
async def get_events(limit: int = Query(default=EVENT_WINDOW_LIMIT, ge=1, le=EVENT_WINDOW_LIMIT)) -> dict:
    return {"events": engine.latest_events(limit=limit)}


@app.get("/api/summary")
async def get_summary() -> dict:
    return engine.summary()


def _build_simulated_request(scenario: str, fixed_ip: str | None = None) -> RequestInput:
    random_ip = fixed_ip or f"10.0.{random.randint(1, 8)}.{random.randint(2, 250)}"
    if scenario == "normal":
        return RequestInput(
            ip_address=random_ip,
            method=random.choice(["GET", "POST"]),
            url=random.choice(["/home", "/products", "/api/profile?id=18", "/search?q=cloud"]),
            payload_text=random.choice(["", "status=active", "sort=desc", "page=2"]),
            form_input=random.choice(["", "name=alex", "city=chennai"]),
            user_agent="Mozilla/5.0",
        )
    if scenario == "sqli":
        return RequestInput(
            ip_address=random_ip,
            method="POST",
            url="/api/login",
            payload_text="' OR 1=1 -- UNION SELECT password FROM users",
            form_input="username=admin",
            user_agent="AttackBot/1.0",
        )
    if scenario == "xss":
        return RequestInput(
            ip_address=random_ip,
            method="POST",
            url="/comments/new",
            payload_text="<script>alert('xss')</script><img src=x onerror=alert(1)>",
            form_input="message=nice post",
            user_agent="AttackBot/1.0",
        )
    if scenario == "anomaly":
        anomaly_payload = "".join(
            random.choice("!@#$%^&*(){}[]<>?/\\|~") for _ in range(ANOMALY_PAYLOAD_LENGTH)
        )
        return RequestInput(
            ip_address=random_ip,
            method="POST",
            url="/api/upload?token=123&mode=raw&unsafe=true",
            payload_text=f"{anomaly_payload} SELECT",
            form_input="",
            user_agent="UnknownClient/9.9",
        )
    if scenario == "ddos":
        return RequestInput(
            ip_address=random_ip,
            method="GET",
            url="/api/heavy-resource?cache=false",
            payload_text="",
            form_input="",
            user_agent="LoadTester/2.3",
        )
    raise HTTPException(status_code=400, detail="Unsupported simulation scenario.")


@app.post("/api/simulate/{scenario}")
async def simulate_traffic(scenario: str, body: SimulateRequest) -> dict:
    scenario = scenario.strip().lower()
    if scenario not in VALID_SCENARIOS:
        raise HTTPException(
            status_code=400,
            detail=f"Scenario must be one of: {', '.join(sorted(VALID_SCENARIOS))}",
        )

    generated: list[dict] = []
    if scenario == "ddos":
        attack_ip = f"172.16.0.{random.randint(2, 254)}"
        for _ in range(body.count):
            generated.append(engine.inspect(_build_simulated_request("ddos", fixed_ip=attack_ip)))
    else:
        for _ in range(body.count):
            generated.append(engine.inspect(_build_simulated_request(scenario)))

    return {
        "scenario": scenario,
        "generated_count": len(generated),
        "latest_event": generated[-1] if generated else None,
    }
