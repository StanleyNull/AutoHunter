import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const appSource = readFileSync(
  fileURLToPath(new URL("../App.vue", import.meta.url)),
  "utf8",
);

describe("应用壳路由动效契约", () => {
  it("不使用 no-op 的 out-in 路由离场，且在新页面挂载后重置并播放入场", () => {
    expect(appSource).not.toContain('<Transition mode="out-in" @enter="onRouteEnter" @leave="onRouteLeave">');
    expect(appSource).toContain('@vue:mounted="onRouteMounted"');
    expect(appSource).toContain("function onRouteMounted(vnode)");
    expect(appSource).toContain("motion.stopAll();");
    expect(appSource).toContain("const root = vnode.el;");
    expect(appSource).toContain("revealPage(root, motion);");
  });
});
