import { describe, it, expect } from "vitest";
import {
  buildLandingDataset,
  countLandingEvents,
  detectLandingFormat,
  isTextualFile,
  splitLandingLines,
} from "@/utils/landingDataset";

describe("detectLandingFormat", () => {
  it("detects JSON arrays and objects by extension and content", () => {
    expect(detectLandingFormat("a.json", '[{"a":1},{"a":2}]')).toBe("JSON");
    expect(detectLandingFormat("a.json", '{"a":1}')).toBe("JSON");
    expect(detectLandingFormat("x", '[{"a":1}]')).toBe("JSON");
  });

  it("detects JSONL by extension or per-line objects", () => {
    expect(detectLandingFormat("a.jsonl", '{"a":1}\n{"a":2}')).toBe("JSONL");
    expect(detectLandingFormat("a.ndjson", '{"a":1}')).toBe("JSONL");
    expect(detectLandingFormat("x", '{"a":1}\n{"b":2}')).toBe("JSONL");
  });

  it("detects LOG by extension or timestamp markers", () => {
    expect(detectLandingFormat("a.log", "hello")).toBe("LOG");
    expect(detectLandingFormat("x", "2026-01-14T09:12:03Z hello")).toBe("LOG");
    expect(detectLandingFormat("x", "Jan 14 09:12:03 host svc: hi")).toBe("LOG");
  });

  it("falls back to TXT", () => {
    expect(detectLandingFormat("a.txt", "just some text")).toBe("TXT");
    expect(detectLandingFormat("x", "hello world")).toBe("TXT");
  });
});

describe("countLandingEvents", () => {
  it("counts JSON arrays by element", () => {
    expect(countLandingEvents('[{"a":1},{"a":2},{"a":3}]', "JSON")).toBe(3);
  });

  it("counts single JSON objects as one event", () => {
    expect(countLandingEvents('{"a":1}', "JSON")).toBe(1);
  });

  it("counts one event per non-empty line otherwise", () => {
    expect(countLandingEvents('a\n\nb\nc\n', "TXT")).toBe(3);
    expect(countLandingEvents('{"a":1}\n{"b":2}', "JSONL")).toBe(2);
  });
});

describe("splitLandingLines", () => {
  it("expands JSON arrays into one line per element", () => {
    expect(splitLandingLines('[{"a":1},{"a":2}]', "JSON")).toEqual(['{"a":1}', '{"a":2}']);
  });

  it("keeps raw lines for text formats", () => {
    expect(splitLandingLines("a\n\nb", "TXT")).toEqual(["a", "b"]);
  });
});

describe("isTextualFile", () => {
  it("accepts log extensions and text mime types", () => {
    expect(isTextualFile("a.json", "")).toBe(true);
    expect(isTextualFile("a.log", "")).toBe(true);
    expect(isTextualFile("a.txt", "text/plain")).toBe(true);
    expect(isTextualFile("a", "application/json")).toBe(true);
  });

  it("rejects binary files", () => {
    expect(isTextualFile("a.exe", "application/x-msdownload")).toBe(false);
    expect(isTextualFile("a.png", "image/png")).toBe(false);
  });
});

describe("buildLandingDataset", () => {
  it("builds metadata without executing content", () => {
    const ds = buildLandingDataset("evil.txt", '<script>alert(1)</script>\nsecond line');
    expect(ds.events).toBe(2);
    expect(ds.format).toBe("TXT");
    expect(ds.preview).toContain("<script>");
    expect(ds.lines).toEqual(['<script>alert(1)</script>', "second line"]);
  });
});
