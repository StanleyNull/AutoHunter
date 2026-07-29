import { describe, expect, it, vi } from "vitest";
import { revealPage, waitForMotion } from "./presets.js";
import { motionTokens } from "./tokens.js";

describe("waitForMotion", () => {
  it("在无动画或动画结束后继续关闭流程", async () => {
    await expect(waitForMotion(null)).resolves.toBeUndefined();

    const resolve = vi.fn();
    const animation = { finished: Promise.resolve().then(resolve) };
    await waitForMotion(animation);

    expect(resolve).toHaveBeenCalledTimes(1);
  });
});


it("halves and caps page staggering on compact viewports", () => {
  const elements = Array.from({ length: 13 }, () => ({ getClientRects: () => [{}] }));
  const motion = { run: vi.fn() };
  const root = { querySelectorAll: () => elements };
  const originalWindow = globalThis.window;
  globalThis.window = { matchMedia: vi.fn(() => ({ matches: true })) };

  revealPage(root, motion);

  const [, parameters] = motion.run.mock.calls[0];
  expect(parameters.delay(elements[12], 12, elements)).toBe((motionTokens.itemDelay / 2) * 8);
  globalThis.window = originalWindow;
});
