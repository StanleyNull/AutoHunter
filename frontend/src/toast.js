import { ref } from "vue";

// 全局右下角 toast 队列，供已完成任务再次启动等场景的轻量提示。
// 支持堆叠：连续触发不同任务时各自独立计时、依次消退。
const list = ref([]);
let seq = 0;

/**
 * 弹出一个右下角提示。
 * @param {string} msg 提示文案
 * @param {number} [ms=5000] 自动消失时长（毫秒）
 */
export function showToast(msg, ms = 5000) {
  if (!msg) return;
  const id = ++seq;
  list.value = [...list.value, { id, msg }];
  setTimeout(() => {
    list.value = list.value.filter((t) => t.id !== id);
  }, ms);
}

export const toastList = list;
