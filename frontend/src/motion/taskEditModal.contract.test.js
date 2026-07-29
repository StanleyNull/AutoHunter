import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

const sourcePath = new URL("../components/TaskEditModal.vue", import.meta.url);

describe("TaskEditModal 保存后关闭流程", () => {
  it("在离场动效结束后发出 saved 事件而非递归调用自身", async () => {
    const source = await readFile(sourcePath, "utf8");
    const implementation = source.match(/async function closeAfterSave\(updated\) \{([\s\S]*?)\n\}/)?.[1] || "";

    expect(implementation).toContain('emit("saved", updated);');
    expect(implementation).not.toContain("await closeAfterSave(updated);");
  });
});
