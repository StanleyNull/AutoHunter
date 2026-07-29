import { stagger } from "animejs";
import { motionTokens } from "./tokens.js";

const visible = (root, selector) => {
  if (!root) return [];

  return [...root.querySelectorAll(selector)]
    .filter((element) => element.getClientRects().length > 0);
};

const asElements = (elements) => [...(elements ?? [])]
  .filter((element) => element?.getClientRects?.().length > 0);

const pageEnterDelay = (_element, index) => {
  const compact = typeof window !== "undefined"
    && window.matchMedia?.("(max-width: 720px)").matches;
  const step = compact ? motionTokens.itemDelay / 2 : motionTokens.itemDelay;
  return Math.min(index, 8) * step;
};

const overlayParameters = (direction, entering) => {
  const offset = motionTokens.enterOffset;
  const isDrawer = direction === "right" || direction === "left";

  if (isDrawer) {
    const signedOffset = direction === "left" ? -offset : offset;
    return {
      opacity: entering ? [0, 1] : [1, 0],
      translateX: entering ? [signedOffset, 0] : [0, signedOffset],
      duration: entering ? motionTokens.standard : motionTokens.quick,
      easing: motionTokens.easing,
    };
  }

  return {
    opacity: entering ? [0, 1] : [1, 0],
    translateY: entering ? [offset, 0] : [0, offset],
    duration: entering ? motionTokens.standard : motionTokens.quick,
    easing: motionTokens.easing,
  };
};

export function revealPage(root, motion) {
  return motion.run(visible(root, "[data-motion-enter]"), {
    opacity: [0, 1],
    translateY: [motionTokens.enterOffset, 0],
    delay: pageEnterDelay,
    duration: motionTokens.page,
    easing: motionTokens.easing,
  });
}

export function revealItems(elements, motion) {
  return motion.run(asElements(elements), {
    opacity: [0, 1],
    translateY: [motionTokens.enterOffset, 0],
    delay: stagger(motionTokens.itemDelay),
    duration: motionTokens.standard,
    easing: motionTokens.easing,
  });
}

export function highlightChanged(elements, motion) {
  const targets = asElements(elements);
  if (!targets.length) return null;

  targets.forEach((element) => element.classList.add("motion-changed"));
  const clearChangedState = () => {
    targets.forEach((element) => element.classList.remove("motion-changed"));
  };
  const animation = motion.run(targets, {
    opacity: [0.82, 1],
    translateY: [-6, 0],
    boxShadow: [
      "0 0 0 0 rgba(85,220,255,0)",
      "0 0 0 1px rgba(102,222,255,.95), 0 0 30px rgba(85,220,255,.52)",
      "0 0 0 0 rgba(85,220,255,0)",
    ],
    scale: [0.992, 1.008, 1],
    duration: motionTokens.emphasis,
    easing: motionTokens.easing,
  });

  if (animation) {
    Promise.resolve(animation.finished).finally(clearChangedState);
  } else {
    setTimeout(clearChangedState, motionTokens.staticFeedback);
  }
  return animation;
}

export function waitForMotion(animation) {
  return animation?.finished ? Promise.resolve(animation.finished) : Promise.resolve();
}

export function enterOverlay(element, motion, direction = "right") {
  return motion.run(element ? [element] : [], overlayParameters(direction, true));
}

export function leaveOverlay(element, motion, direction = "right") {
  return motion.run(element ? [element] : [], overlayParameters(direction, false));
}
