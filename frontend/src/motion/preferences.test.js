import { describe, expect, it } from "vitest";
import { createMotionPreference } from "./preferences.js";

describe("createMotionPreference", () => {
  it("读取媒体查询初始值并停止订阅", () => {
    const listeners = new Set();
    const media = {
      matches: true,
      addEventListener: (_name, listener) => listeners.add(listener),
      removeEventListener: (_name, listener) => listeners.delete(listener),
    };

    const preference = createMotionPreference(media);
    expect(preference.reduced.value).toBe(true);
    expect(listeners.size).toBe(1);
    preference.stop();
    expect(listeners.size).toBe(0);
  });
});
