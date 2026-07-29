import { ref } from "vue";

export function createMotionPreference(mediaQueryList) {
  const reduced = ref(Boolean(mediaQueryList?.matches));
  const onChange = (event) => { reduced.value = event.matches; };
  mediaQueryList?.addEventListener?.("change", onChange);

  return {
    reduced,
    stop() {
      mediaQueryList?.removeEventListener?.("change", onChange);
    },
  };
}
