import test from "node:test";
import assert from "node:assert/strict";
import { effectScope, ref } from "vue";
import { usePagedList } from "../src/composables/usePagedList.js";

function setup(t, fetchPage, pageSize = 2) {
  const task = ref("a");
  const search = ref("");
  const scope = effectScope();
  const page = scope.run(() => usePagedList(() => [task.value, search.value], fetchPage, pageSize));
  t.after(() => scope.stop());
  return { page, task, search, scope };
}
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

test("concurrent refreshes share one request", async (t) => {
  const request = deferred();
  let calls = 0;
  const { page } = setup(t, () => { calls++; return request.promise; });
  const first = page.load();
  assert.equal(page.load(), first);
  await Promise.resolve();
  assert.equal(calls, 1);
  assert.equal(page.loading.value, true);
  request.resolve({ items: [{ id: 1 }], has_more: true });
  await first;
  assert.equal(page.items.value.length, 1);
  assert.equal(page.loading.value, false);
  assert.equal(page.hasMore.value, true);
});

test("late responses cannot overwrite a new task or search", async (t) => {
  const old = deferred();
  const { page, task, search } = setup(t, ([id, query]) =>
    id === "a" ? old.promise : Promise.resolve({ items: [{ id, query }], has_more: false }));
  const first = page.load();
  task.value = "b";
  search.value = "report body";
  await page.load();
  old.resolve({ items: [{ id: "stale" }], has_more: true });
  assert.equal(await first, false);
  assert.deepEqual(page.items.value, [{ id: "b", query: "report body" }]);
});

test("refresh keeps the current page and search resets pagination", async (t) => {
  const calls = [];
  const { page, search } = setup(t, async (context, paging) => {
    calls.push({ context, ...paging });
    return { items: [{ id: paging.offset }], has_more: true };
  });
  await page.load(2);
  await page.load();
  assert.equal(page.offset.value, 2);
  assert.deepEqual(calls.map(c => c.offset), [2, 2]);
  search.value = "new query";
  assert.deepEqual(page.items.value, []);
  await page.load();
  assert.equal(calls[2].offset, 0);
  assert.equal(calls[2].context[1], "new query");
});

test("failed navigation keeps the displayed page and supports retry", async (t) => {
  let fail = false;
  const { page } = setup(t, async (_, { offset }) => {
    if (fail) throw new Error("offline");
    return { items: [{ id: offset }], has_more: true };
  });
  await page.load();
  fail = true;
  assert.equal(await page.load(2), false);
  assert.equal(page.offset.value, 0);
  assert.deepEqual(page.items.value, [{ id: 0 }]);
  assert.match(page.error.value, /offline/);
  assert.equal(page.loading.value, false);
  fail = false;
  assert.equal(await page.load(2), true);
  assert.equal(page.error.value, "");
});

test("an emptied last page falls back to the preceding page", async (t) => {
  const { page } = setup(t, async (_, { offset }) => ({
    items: offset ? [] : [{ id: "remaining" }], has_more: false,
  }));
  await page.load(2);
  assert.equal(page.offset.value, 0);
  assert.deepEqual(page.items.value, [{ id: "remaining" }]);
  assert.equal(page.loading.value, false);
});

test("unmounted lists ignore pending responses", async (t) => {
  const pending = deferred();
  const { page, scope } = setup(t, () => pending.promise);
  const request = page.load();
  scope.stop();
  pending.resolve({ items: [{ id: "old" }], has_more: true });
  assert.equal(await request, false);
  assert.deepEqual(page.items.value, []);
});


test("polling during navigation shares the requested page", async (t) => {
  const next = deferred();
  const { page } = setup(t, (_, { offset }) => offset ? next.promise : Promise.resolve({ items: [{ id: 0 }], has_more: true }));
  await page.load();
  const navigation = page.load(2);
  assert.equal(page.load(), navigation);
  next.resolve({ items: [{ id: 2 }], has_more: false });
  await navigation;
  assert.equal(page.offset.value, 2);
});
