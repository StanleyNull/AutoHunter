import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

const sourcePath = new URL("../components/LlmPoolEditor.vue", import.meta.url);

describe("LlmPoolEditor 结构动效契约", () => {
  it("仅对新增、删除和重排的端点行执行局部反馈", async () => {
    const source = await readFile(sourcePath, "utf8");

    expect(source).toContain('data-motion-enter');
    expect(source).toContain('revealItems(row ? [row] : [], motion);');
    expect(source).toContain('await waitForMotion(motion.run(row ? [row] : [], {');
    expect(source).toContain('getBoundingClientRect().top');
  });
});
