import { describe, expect, it, vi } from "vitest";
import { createMotionRunner } from "./useMotion.js";

describe("createMotionRunner", () => {
  it("减少动态效果时跳过 Anime.js 工厂", () => {
    const animate = vi.fn();
    const runner = createMotionRunner({ animate, reduced: { value: true } });

    expect(runner.run([{}], { opacity: [0, 1] })).toBeNull();
    expect(animate).not.toHaveBeenCalled();
  });
});
