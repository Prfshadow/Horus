import { describe, it, expect } from "vitest";
import { buildScenario, scenarioSourceIps, SCENARIO_ORDER } from "@/utils/syntheticScenarios";

const PINNED_NOW = new Date("2026-09-22T10:13:09Z").getTime();

describe("buildScenario", () => {
  it("produces parseable synthetic lines for every scenario", () => {
    for (const name of SCENARIO_ORDER) {
      const { lines } = buildScenario(name, { seed: 7, now: PINNED_NOW });
      expect(lines.length).toBeGreaterThan(5);
      for (const line of lines) {
        const obj = JSON.parse(line) as Record<string, unknown>;
        expect(obj.synthetic).toBe(true);
        expect(typeof obj.scenario).toBe("string");
        expect(typeof obj.timestamp).toBe("string");
      }
    }
  });

  it("is deterministic for a fixed seed", () => {
    expect(buildScenario("authentication_attack", { seed: 11, now: PINNED_NOW })).toEqual(
      buildScenario("authentication_attack", { seed: 11, now: PINNED_NOW }),
    );
  });

  it("varies with different seeds", () => {
    expect(buildScenario("network_reconnaissance", { seed: 1, now: PINNED_NOW })).not.toEqual(
      buildScenario("network_reconnaissance", { seed: 2, now: PINNED_NOW }),
    );
  });

  it("uses only documentation IP ranges", () => {
    const ipRe = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/g;
    for (const name of SCENARIO_ORDER) {
      const { lines } = buildScenario(name, { seed: 13, now: PINNED_NOW });
      for (const line of lines) {
        for (const match of line.matchAll(ipRe)) {
          const ip = match[1] ?? "";
          const ok =
            ip.startsWith("192.0.2.") ||
            ip.startsWith("198.51.100.") ||
            ip.startsWith("203.0.113.") ||
            ip.startsWith("10.");
          expect(ok, `${name}: ${ip}`).toBe(true);
        }
      }
    }
  });

  it("contains no secrets or exploit payloads", () => {
    const forbidden = ["password=", "passwd", "api_key", "BEGIN PRIVATE", "<script", "UNION SELECT", "DROP TABLE", "/etc/passwd", "mimikatz"];
    for (const name of SCENARIO_ORDER) {
      const { lines } = buildScenario(name, { seed: 17, now: PINNED_NOW });
      for (const line of lines) {
        for (const bad of forbidden) {
          expect(line.toLowerCase().includes(bad.toLowerCase()), `${name} contains ${bad}`).toBe(false);
        }
      }
    }
  });

  it("multi-stage contains the expected progression", () => {
    const { lines } = buildScenario("multi_stage_incident", { seed: 42, now: PINNED_NOW });
    const blob = lines.join("\n");
    expect(blob).toContain("login_failed");
    expect(blob).toContain("login_success");
    expect(blob).toContain("Domain Admins");
    expect(blob).toContain("powershell");
    expect(blob).toContain("evil.example");
    expect(blob).toContain("bytes_sent");
  });

  it("random picks a valid scenario", () => {
    const { name, lines } = buildScenario("random", { seed: 3, now: PINNED_NOW });
    expect(SCENARIO_ORDER).toContain(name);
    expect(lines.length).toBeGreaterThan(5);
  });
});

describe("scenarioSourceIps", () => {
  it("extracts synthetic source IPs", () => {
    const { lines } = buildScenario("authentication_attack", { seed: 9, now: PINNED_NOW });
    const ips = scenarioSourceIps(lines);
    expect(ips.length).toBeGreaterThanOrEqual(1);
  });
});
