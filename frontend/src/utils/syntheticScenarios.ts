/**
 * Synthetic Threat Lab scenario builders (SYNTHETIC / DEMO DATA only).
 *
 * Every line is a JSON log marked `synthetic: true` with a `scenario` name,
 * using documentation IP ranges (192.0.2.0/24, 198.51.100.0/24,
 * 203.0.113.0/24). Lines go through the REAL POST /api/v1/ingest pipeline —
 * nothing is faked server-side. Timestamps land in the last few minutes so
 * default detection/correlation windows catch them.
 *
 * Bursts are timed to sit inside rule windows (suspicious events end ~10s
 * ago and span at most ~45s) so BruteForce (5+/60s), PortScan (10+/60s) and
 * WebScan (8+/60s) fire deterministically.
 */

export type ScenarioName =
  | "authentication_attack"
  | "network_reconnaissance"
  | "web_application_attack"
  | "malware_detection"
  | "privilege_escalation"
  | "data_transfer_anomaly"
  | "multi_stage_incident"
  | "mostly_normal"
  | "random";

export const SCENARIO_META: Record<
  Exclude<ScenarioName, "random">,
  { label: string; tagline: string; expects: string }
> = {
  authentication_attack: {
    label: "Authentication Attack",
    tagline: "Brute-force burst on one account",
    expects: "Expect BruteForceLogin alert → incident.",
  },
  network_reconnaissance: {
    label: "Network Reconnaissance",
    tagline: "One source probing many ports",
    expects: "Expect PortScan alert → incident.",
  },
  web_application_attack: {
    label: "Web Application Attack",
    tagline: "Suspicious endpoints + injection probes",
    expects: "Expect WebScan / SQLInjection / XSSAttempt alerts.",
  },
  malware_detection: {
    label: "Malware Detection",
    tagline: "Endpoint ransomware verdict",
    expects: "Expect MalwareDetection (CRITICAL) alert.",
  },
  privilege_escalation: {
    label: "Privilege Escalation",
    tagline: "Developer → Domain Admins",
    expects: "Expect PrivilegeEscalation alert.",
  },
  data_transfer_anomaly: {
    label: "Data Transfer Anomaly",
    tagline: "Large outbound transfer",
    expects: "Expect DataTransferAnomaly alert.",
  },
  multi_stage_incident: {
    label: "Multi-Stage Incident",
    tagline: "Auth → privilege → endpoint → exfil",
    expects: "Expect multiple alerts correlated into 1 incident.",
  },
  mostly_normal: {
    label: "Mostly Normal",
    tagline: "Benign traffic, no attack",
    expects: "No alerts expected — proves HORUS doesn't cry wolf.",
  },
};

export const SCENARIO_ORDER: Exclude<ScenarioName, "random">[] = [
  "authentication_attack",
  "network_reconnaissance",
  "web_application_attack",
  "malware_detection",
  "privilege_escalation",
  "data_transfer_anomaly",
  "multi_stage_incident",
  "mostly_normal",
];

const DOC_IPS = [
  "192.0.2.5",
  "192.0.2.10",
  "192.0.2.44",
  "198.51.100.7",
  "198.51.100.30",
  "198.51.100.40",
  "203.0.113.9",
  "203.0.113.20",
  "203.0.113.50",
  "203.0.113.99",
];
const USERS = ["alice", "bob", "carol", "dave", "erin", "svc-deploy"];
const HOSTS = ["web-01", "web-02", "api-01", "ws-01", "srv-01"];
const BENIGN_MESSAGES = [
  "Request completed",
  "Cache hit for /api/v1/health",
  "Worker heartbeat",
  "DB query finished",
  "Static asset served",
];
const SUSPICIOUS_PATHS = ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config", "/backup", "/login", "/api/debug"];

export function mulberry32(seed: number): () => number {
  let a = seed;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pick<T>(rng: () => number, arr: readonly T[]): T {
  return arr[Math.floor(rng() * arr.length)] as T;
}

function jsonLine(obj: Record<string, unknown>): string {
  return JSON.stringify(obj);
}

function baseLine(
  ts: number,
  level: string,
  message: string,
  source: string,
  extra: Record<string, unknown> | undefined,
  host: string,
  service: string | undefined,
  scenario: string,
): string {
  return jsonLine({
    timestamp: new Date(ts).toISOString(),
    level,
    message,
    source,
    service: service ?? source,
    host,
    synthetic: true,
    scenario,
    ...(extra ?? {}),
  });
}

function benignLine(rng: () => number, ts: number, scenario: string): string {
  const service = pick(rng, ["api", "search", "payments"]);
  return baseLine(
    ts,
    rng() < 0.9 ? "INFO" : "WARNING",
    `${pick(rng, BENIGN_MESSAGES)} #${Math.floor(rng() * 9000)}`,
    service,
    undefined,
    pick(rng, HOSTS),
    service,
    scenario,
  );
}

function spreadTimes(rng: () => number, now: number, count: number, spanSeconds: number, endOffsetSeconds: number): number[] {
  const start = now - (endOffsetSeconds + spanSeconds) * 1000;
  const step = (spanSeconds * 1000) / Math.max(count, 1);
  const out: number[] = [];
  for (let i = 0; i < count; i += 1) {
    out.push(start + i * step + (rng() * 3000 - 1500));
  }
  return out.sort((a, b) => a - b);
}

export type ScenarioOptions = {
  seed?: number;
  now?: number;
};

function buildAuthenticationAttack(rng: () => number, now: number): string[] {
  const ip = pick(rng, DOC_IPS);
  const user = pick(rng, USERS);
  const host = pick(rng, HOSTS);
  const count = 6 + Math.floor(rng() * 4);
  const out: Array<{ ts: number; line: string }> = [];
  for (const ts of spreadTimes(rng, now, count, 35, 10)) {
    out.push({
      ts,
      line: baseLine(ts, "ERROR", `Failed password for ${user} from ${ip}`, "auth-service", { ip, user }, host, "sshd", "authentication_attack"),
    });
  }
  for (const ts of spreadTimes(rng, now, 25, 220, 20)) out.push({ ts, line: benignLine(rng, ts, "authentication_attack") });
  return out.sort((a, b) => a.ts - b.ts).map((l) => l.line);
}

function buildNetworkReconnaissance(rng: () => number, now: number): string[] {
  const ip = pick(rng, DOC_IPS);
  const host = pick(rng, HOSTS);
  const ports = [...Array(5000).keys()].map((p) => p + 20).sort(() => rng() - 0.5).slice(0, 11);
  const out: Array<{ ts: number; line: string }> = [];
  spreadTimes(rng, now, 11, 45, 8).forEach((ts, i) => {
    out.push({
      ts,
      line: baseLine(ts, "WARNING", `connection attempt to port ${ports[i]}`, "firewall", { ip, destination_port: ports[i] }, host, "firewall", "network_reconnaissance"),
    });
  });
  for (const ts of spreadTimes(rng, now, 25, 220, 20)) out.push({ ts, line: benignLine(rng, ts, "network_reconnaissance") });
  return out.sort((a, b) => a.ts - b.ts).map((l) => l.line);
}

function buildWebApplicationAttack(rng: () => number, now: number): string[] {
  const ip = pick(rng, DOC_IPS);
  const host = pick(rng, HOSTS);
  const out: Array<{ ts: number; line: string }> = [];
  spreadTimes(rng, now, SUSPICIOUS_PATHS.length, 45, 8).forEach((ts, i) => {
    const path = SUSPICIOUS_PATHS[i];
    out.push({
      ts,
      line: baseLine(ts, "INFO", `GET ${path}`, "web", { ip, path, method: "GET", status_code: 404 }, host, "web", "web_application_attack"),
    });
  });
  const sqliTs = now - 25000;
  out.push({ ts: sqliTs, line: baseLine(sqliTs, "INFO", "GET /search", "web", { ip, attack_type: "sqli", path: "/search" }, host, "web", "web_application_attack") });
  const xssTs = now - 20000;
  out.push({ ts: xssTs, line: baseLine(xssTs, "INFO", "GET /comment", "web", { ip, attack_type: "xss", path: "/comment" }, host, "web", "web_application_attack") });
  for (const ts of spreadTimes(rng, now, 25, 220, 20)) out.push({ ts, line: benignLine(rng, ts, "web_application_attack") });
  return out.sort((a, b) => a.ts - b.ts).map((l) => l.line);
}

function buildMalwareDetection(rng: () => number, now: number): string[] {
  const host = pick(rng, HOSTS);
  const out: Array<{ ts: number; line: string }> = [
    { ts: now - 40000, line: baseLine(now - 40000, "WARNING", "threat blocked", "endpoint", { detection_type: "ransomware_detected", threat_name: "BlackCat" }, host, "endpoint", "malware_detection") },
  ];
  for (const ts of spreadTimes(rng, now, 25, 220, 20)) out.push({ ts, line: benignLine(rng, ts, "malware_detection") });
  return out.sort((a, b) => a.ts - b.ts).map((l) => l.line);
}

function buildPrivilegeEscalation(rng: () => number, now: number): string[] {
  const host = pick(rng, HOSTS);
  const user = pick(rng, USERS);
  const out: Array<{ ts: number; line: string }> = [
    { ts: now - 40000, line: baseLine(now - 40000, "WARNING", "role change", "iam", { old_role: "developer", new_role: "Domain Admins", target_user: user }, host, "iam", "privilege_escalation") },
  ];
  for (const ts of spreadTimes(rng, now, 25, 220, 20)) out.push({ ts, line: benignLine(rng, ts, "privilege_escalation") });
  return out.sort((a, b) => a.ts - b.ts).map((l) => l.line);
}

function buildDataTransferAnomaly(rng: () => number, now: number): string[] {
  const ip = pick(rng, DOC_IPS);
  const host = pick(rng, HOSTS);
  const out: Array<{ ts: number; line: string }> = [
    { ts: now - 40000, line: baseLine(now - 40000, "INFO", "transfer", "firewall", { bytes_sent: 200 * 1024 * 1024, direction: "outbound", destination_ip: "203.0.113.99", ip }, host, "firewall", "data_transfer_anomaly") },
  ];
  for (const ts of spreadTimes(rng, now, 25, 220, 20)) out.push({ ts, line: benignLine(rng, ts, "data_transfer_anomaly") });
  return out.sort((a, b) => a.ts - b.ts).map((l) => l.line);
}

function buildMultiStage(rng: () => number, now: number): string[] {
  const ip = "203.0.113.99";
  const host = "web-01";
  const user = "alice";
  const t0 = now - 230000;
  const at = (offsetSeconds: number) => t0 + offsetSeconds * 1000;
  const out: Array<{ ts: number; line: string }> = [];
  for (let i = 0; i < 8; i += 1) {
    const ts = at(5 + i * 5);
    out.push({ ts, line: benignLine(rng, ts, "multi_stage_incident") });
  }
  ["alice", "bob", "carol", "dave", "erin"].forEach((u, i) => {
    const ts = at(60 + i * 6);
    out.push({ ts, line: baseLine(ts, "ERROR", `Failed password for ${u} from ${ip}`, "auth-service", { ip, user: u }, host, "sshd", "multi_stage_incident") });
  });
  for (let i = 0; i < 5; i += 1) {
    const ts = at(95 + i * 6);
    out.push({ ts, line: baseLine(ts, "ERROR", "login failed", "auth-service", { user, ip, action: "login_failed" }, host, "sshd", "multi_stage_incident") });
  }
  out.push({ ts: at(130), line: baseLine(at(130), "INFO", "login ok", "auth-service", { user, ip, action: "login_success" }, host, "sshd", "multi_stage_incident") });
  out.push({ ts: at(145), line: baseLine(at(145), "WARNING", "role change", "iam", { old_role: "developer", new_role: "Domain Admins", target_user: user, ip }, host, "iam", "multi_stage_incident") });
  out.push({ ts: at(160), line: baseLine(at(160), "WARNING", "process", "edr", { process: "powershell.exe", parent_process: "winword.exe", ip }, host, "edr", "multi_stage_incident") });
  out.push({ ts: at(175), line: baseLine(at(175), "WARNING", "bad domain", "dns", { domain: "evil.example", verdict: "malicious", ip }, host, "dns", "multi_stage_incident") });
  out.push({ ts: at(190), line: baseLine(at(190), "INFO", "transfer", "firewall", { bytes_sent: 200 * 1024 * 1024, direction: "outbound", destination_ip: "203.0.113.99", ip }, host, "firewall", "multi_stage_incident") });
  for (let i = 0; i < 8; i += 1) {
    const ts = at(200 + i * 3);
    out.push({ ts, line: benignLine(rng, ts, "multi_stage_incident") });
  }
  return out.sort((a, b) => a.ts - b.ts).map((l) => l.line);
}

function buildMostlyNormal(rng: () => number, now: number): string[] {
  const out = spreadTimes(rng, now, 42, 220, 20).map((ts) => ({ ts, line: benignLine(rng, ts, "mostly_normal") }));
  return out.sort((a, b) => a.ts - b.ts).map((l) => l.line);
}

const BUILDERS: Record<Exclude<ScenarioName, "random">, (rng: () => number, now: number) => string[]> = {
  authentication_attack: buildAuthenticationAttack,
  network_reconnaissance: buildNetworkReconnaissance,
  web_application_attack: buildWebApplicationAttack,
  malware_detection: buildMalwareDetection,
  privilege_escalation: buildPrivilegeEscalation,
  data_transfer_anomaly: buildDataTransferAnomaly,
  multi_stage_incident: buildMultiStage,
  mostly_normal: buildMostlyNormal,
};

/** Build a scenario's raw log lines. `random` picks a scenario and randomizes it. */
export function buildScenario(name: ScenarioName, opts?: ScenarioOptions): { name: Exclude<ScenarioName, "random">; lines: string[] } {
  const seed = opts?.seed ?? Math.floor(Math.random() * 2 ** 31);
  const now = opts?.now ?? Date.now();
  if (name === "random") {
    const rng = mulberry32(seed);
    const choice = SCENARIO_ORDER[Math.floor(rng() * (SCENARIO_ORDER.length - 1))];
    const scenario = (choice ?? "authentication_attack") as Exclude<ScenarioName, "random">;
    return { name: scenario, lines: BUILDERS[scenario](mulberry32(seed ^ 0x9e3779b9), now) };
  }
  return { name, lines: BUILDERS[name](mulberry32(seed), now) };
}

/** Attacker/source IPs embedded in a generated batch (for result banners). */
export function scenarioSourceIps(lines: string[]): string[] {
  const ips = new Set<string>();
  for (const line of lines) {
    try {
      const obj = JSON.parse(line) as { level?: string; ip?: unknown; synthetic?: unknown };
      if (obj.synthetic === true && typeof obj.ip === "string") ips.add(obj.ip);
    } catch {
      // ignore unparsable lines
    }
  }
  return [...ips].sort();
}
