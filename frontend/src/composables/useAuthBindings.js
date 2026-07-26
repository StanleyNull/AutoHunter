// 目标凭据绑定（auth bindings）的共享逻辑：新建任务（CreateView）与编辑任务
// （TaskEditModal）两处一字不差地重复过这套 ref + 增删 + 导出 + 选项计算，抽成
// composable 单一真相。行为完全保持：返回同一个 authBindings ref 与同名函数，
// 调用方的 watch / v-model / loadAuthBindings 都作用在同一身份上。
import { ref, computed } from "vue";

export function emptyBinding() {
  return {
    target: "*", raw: "", username: "", password: "",
    cookie: "", authorization: "", login_url: "", note: "",
  };
}

/**
 * @param {() => string} manualTargetsGetter 返回“手动目标清单”多行文本（各组件的 form.manual_targets）
 */
export function useAuthBindings(manualTargetsGetter) {
  const authBindings = ref([emptyBinding()]);

  const manualTargetLines = computed(() =>
    String(manualTargetsGetter() || "").split("\n").map((s) => s.trim()).filter(Boolean)
  );

  const bindingOptions = computed(() => {
    const opts = [{ value: "*", label: "*（全部目标默认）" }];
    for (const line of manualTargetLines.value) {
      opts.push({ value: line, label: line });
    }
    return opts;
  });

  function addBinding() {
    authBindings.value.push(emptyBinding());
  }
  function removeBinding(i) {
    authBindings.value.splice(i, 1);
    if (!authBindings.value.length) authBindings.value.push(emptyBinding());
  }
  function exportAuthBindings() {
    return authBindings.value
      .map((b) => ({
        target: (b.target || "*").trim() || "*",
        username: (b.username || "").trim(),
        password: (b.password || "").trim(),
        cookie: (b.cookie || "").trim(),
        authorization: (b.authorization || "").trim(),
        login_url: (b.login_url || "").trim(),
        raw: (b.raw || "").trim(),
        note: (b.note || "").trim(),
      }))
      .filter((b) => b.username || b.password || b.cookie || b.authorization || b.raw);
  }

  return {
    authBindings,
    emptyBinding,
    addBinding,
    removeBinding,
    exportAuthBindings,
    bindingOptions,
    manualTargetLines,
  };
}
