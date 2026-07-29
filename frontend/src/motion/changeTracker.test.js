import { describe, expect, it } from "vitest";
import { createChangeTracker } from "./changeTracker.js";

const tracker = () => createChangeTracker({
  getId: (item) => item.id,
  getSignature: (item) => `${item.status}|${item.updated_at}|${item.count}`,
});

describe("createChangeTracker", () => {
  it("首屏 seed 后不会把既有条目标为变化", () => {
    const subject = tracker();
    const rows = [{ id: "a", status: "running", updated_at: "1", count: 1 }];
    subject.seed(rows);
    expect(subject.diff(rows)).toEqual(new Set());
  });

  it("仅返回新增或关键字段变化的稳定 ID", () => {
    const subject = tracker();
    subject.seed([{ id: "a", status: "running", updated_at: "1", count: 1 }]);
    expect(subject.diff([
      { id: "a", status: "done", updated_at: "2", count: 1 },
      { id: "b", status: "queued", updated_at: "1", count: 0 },
    ])).toEqual(new Set(["a", "b"]));
  });
});
