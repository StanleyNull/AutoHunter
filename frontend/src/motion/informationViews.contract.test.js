import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

const viewNames = ["IntelView", "VulnsView", "HardTargetsView", "RuntimeLogsView"];

async function sourceOf(viewName) {
  return readFile(new URL(`../views/${viewName}.vue`, import.meta.url), "utf8");
}

describe("信息密集页面动效契约", () => {
  it("为所有列表建立独立变更追踪，并为真实行提供稳定动效锚点", async () => {
    const sources = await Promise.all(viewNames.map(sourceOf));

    for (const source of sources) {
      expect(source).toContain("createChangeTracker");
      expect(source).toContain("tracker.seed(rows.value)");
      expect(source).toContain("data-motion-id");
      expect(source).toContain("data-motion-enter");
      expect(source).toContain("data-motion-area");
      expect(source).toContain("const hasLoaded = ref(false);");
    }
  });

  it("只向变化数据执行局部动效，运行日志新增时使用入场反馈", async () => {
    const [intel, vulns, hardTargets, runtimeLogs] = await Promise.all(viewNames.map(sourceOf));

    for (const source of [intel, vulns, hardTargets]) {
      expect(source).toContain("highlightChanged(changedElements, motion);");
      expect(source).toContain("await nextTick();");
    }
    expect(runtimeLogs).toContain("revealItems(changedElements, motion);");
    expect(runtimeLogs).not.toContain("scrollTop");
  });
});
