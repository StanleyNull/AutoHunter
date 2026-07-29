import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const stylesheet = readFileSync(
  fileURLToPath(new URL("../style.css", import.meta.url)),
  "utf8",
);

const darkTheme = stylesheet.match(
  /:root,\s*:root\[data-theme="dark"\]\s*\{([\s\S]*?)\n\}/,
)?.[1] || "";

describe("orbital glass theme tokens", () => {
  it("defines every orbital token for the default dark theme", () => {
    for (const token of [
      "--orbital-void",
      "--orbital-glass",
      "--orbital-glass-strong",
      "--orbital-border",
      "--orbital-highlight",
      "--orbital-grid",
      "--orbital-glow",
    ]) {
      expect(darkTheme).toContain(token);
    }
  });
  it("uses high-contrast cyber command tokens in the default dark theme", () => {
    expect(darkTheme).toContain("--orbital-void: oklch(12% 0.035 258)");
    expect(darkTheme).toContain("--orbital-border: oklch(78% 0.16 225 / 0.42)");
    expect(darkTheme).toContain("--orbital-glow: oklch(76% 0.2 225 / 0.24)");
    expect(darkTheme).toContain("--orbital-grid: oklch(72% 0.13 230 / 0.1)");
  });
});
