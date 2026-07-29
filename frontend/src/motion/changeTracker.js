export function createChangeTracker({ getId, getSignature }) {
  let snapshots = new Map();

  function toSnapshots(items) {
    return new Map(items.map((item) => [String(getId(item)), getSignature(item)]));
  }

  return {
    seed(items) {
      snapshots = toSnapshots(items);
    },
    diff(items) {
      const next = toSnapshots(items);
      const changed = new Set();
      for (const [id, signature] of next) {
        if (!snapshots.has(id) || snapshots.get(id) !== signature) changed.add(id);
      }
      snapshots = next;
      return changed;
    },
    reset() {
      snapshots = new Map();
    },
  };
}
