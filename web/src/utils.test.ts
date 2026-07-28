import { describe, expect, it } from "vitest";
import { formatBytes, formatDate, formatTime } from "./utils";

describe("display formatting", () => {
  it("uses readable binary units and keeps byte precision", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(1024 * 1024 * 2.5)).toBe("2.5 MB");
  });

  it("formats timestamps without throwing for valid ISO values", () => {
    const value = "2026-07-28T12:34:56.000Z";
    expect(formatTime(value)).toMatch(/\d{2}:\d{2}:\d{2}/);
    expect(formatDate(value)).toContain("2026");
  });
});

