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
});
