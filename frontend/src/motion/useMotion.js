import { animate } from "animejs";
import { onBeforeUnmount } from "vue";
import { createMotionPreference } from "./preferences.js";

export function createMotionRunner({ animate: animateFactory = animate, reduced }) {
  const active = new Set();

  return {
    run(targets, parameters) {
      if (reduced.value || !targets?.length) return null;

      const animation = animateFactory(targets, parameters);
      active.add(animation);
      Promise.resolve(animation.finished).finally(() => active.delete(animation));
      return animation;
    },
    stopAll() {
      active.forEach((animation) => animation.pause?.());
      active.clear();
    },
  };
}

export function useMotion() {
  const preference = createMotionPreference(
    window.matchMedia("(prefers-reduced-motion: reduce)"),
  );
  const runner = createMotionRunner({ reduced: preference.reduced });

  onBeforeUnmount(() => {
    runner.stopAll();
    preference.stop();
  });

  return { reduced: preference.reduced, ...runner };
}
