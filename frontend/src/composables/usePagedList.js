import { ref, watch, onScopeDispose } from "vue";

// One visible page; polling reuses in-flight work and never replaces a newer
// task/search/page with a late response from an older request.
export function usePagedList(context, fetchPage, pageSize = 50) {
  const items = ref([]);
  const offset = ref(0);
  const hasMore = ref(false);
  const loading = ref(false);
  const error = ref("");
  let generation = 0;
  let pending = null;

  function reset() {
    generation++;
    pending = null;
    items.value = [];
    offset.value = 0;
    hasMore.value = false;
    loading.value = false;
    error.value = "";
  }

  function load(nextOffset = pending?.offset ?? offset.value) {
    const requestContext = context();
    const key = JSON.stringify([requestContext, nextOffset]);
    if (pending?.key === key) return pending.promise;
    const version = ++generation;
    const previousOffset = offset.value;
    loading.value = true;
    error.value = "";
    const promise = (async () => {
      try {
        const result = await Promise.resolve().then(() => fetchPage(requestContext, { limit: pageSize, offset: nextOffset }));
        if (version !== generation) return false;
        const rows = Array.isArray(result) ? result : (result.items || []);
        // Reviewing the last item on a page may empty it. Return to the
        // preceding page so the queue does not appear empty while items remain.
        if (!rows.length && nextOffset > 0) return load(Math.max(0, nextOffset - pageSize));
        items.value = rows;
        offset.value = nextOffset;
        hasMore.value = !!result.has_more;
        return true;
      } catch (e) {
        if (version === generation) {
          offset.value = previousOffset;
          error.value = `加载失败：${e?.message || e}`;
        }
        return false;
      } finally {
        if (version === generation) {
          loading.value = false;
          pending = null;
        }
      }
    })();
    pending = { key, promise, offset: nextOffset };
    return promise;
  }

  watch(context, reset, { flush: "sync" });
  onScopeDispose(reset);
  return { items, offset, hasMore, loading, error, load, reset, pageSize };
}
