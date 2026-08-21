/** 外观偏好：服务端持久化，localStorage 只做启动缓存。 */

export const UI_STORAGE_KEY = "ah-ui";
export const THEME_STORAGE_KEY = "ah-theme";
const MIGRATED_KEY = "ah-ui-migrated";

export const ACCENT_PRESETS = [
  { h: 235, name: "青蓝" },
  { h: 175, name: "青绿" },
  { h: 85, name: "琥珀" },
  { h: 25, name: "珊瑚" },
  { h: 310, name: "紫" },
  { h: 255, name: "靛" },
];

export const DEFAULTS = {
  theme: "dark",
  accentHue: 235,
  wallpaperKind: "none",
  wallpaperUrl: "",
  wallpaperFit: "cover",
  wallpaperDim: 0.28,
};

let appliedSrc = "";

function clampHue(h) {
  const n = Number(h);
  if (!Number.isFinite(n)) return DEFAULTS.accentHue;
  return Math.max(0, min360(Math.round(n)));
}
function min360(n) { return Math.max(0, Math.min(360, n)); }

function clampDim(d) {
  const n = Number(d);
  if (!Number.isFinite(n)) return DEFAULTS.wallpaperDim;
  if (n >= 0.65) return DEFAULTS.wallpaperDim;
  return Math.max(0.08, Math.min(0.62, n));
}

export function prefsFromApi(ui = {}) {
  return {
    theme: ui.theme === "light" ? "light" : "dark",
    accentHue: clampHue(ui.accentHue),
    wallpaperKind: ["none", "url", "file"].includes(ui.wallpaperKind) ? ui.wallpaperKind : "none",
    wallpaperUrl: typeof ui.wallpaperUrl === "string" ? ui.wallpaperUrl.trim() : "",
    wallpaperFit: ui.wallpaperFit === "contain" ? "contain" : "cover",
    wallpaperDim: clampDim(ui.wallpaperDim),
    wallpaperSrc: typeof ui.wallpaperSrc === "string" ? ui.wallpaperSrc : "",
  };
}

export function prefsToApi(prefs) {
  return {
    theme: prefs.theme,
    accentHue: clampHue(prefs.accentHue),
    wallpaperKind: prefs.wallpaperKind,
    wallpaperUrl: prefs.wallpaperUrl || "",
    wallpaperFit: prefs.wallpaperFit,
    wallpaperDim: clampDim(prefs.wallpaperDim),
    saved: true,
  };
}

export function loadUiPrefs() {
  let parsed = {};
  try {
    parsed = JSON.parse(localStorage.getItem(UI_STORAGE_KEY) || "{}") || {};
  } catch {
    parsed = {};
  }
  const legacyTheme = localStorage.getItem(THEME_STORAGE_KEY);
  return prefsFromApi({
    ...parsed,
    theme: parsed.theme || (legacyTheme === "light" ? "light" : DEFAULTS.theme),
  });
}

export function saveUiPrefs(prefs) {
  const next = { ...DEFAULTS, ...prefs };
  localStorage.setItem(UI_STORAGE_KEY, JSON.stringify(next));
  localStorage.setItem(THEME_STORAGE_KEY, next.theme);
  return next;
}

export function applyChrome(prefs) {
  const root = document.documentElement;
  root.setAttribute("data-theme", prefs.theme);
  root.style.setProperty("--accent-h", String(prefs.accentHue));
  root.style.setProperty("--wallpaper-dim", String(prefs.wallpaperDim));
  root.style.setProperty("--wallpaper-fit", prefs.wallpaperFit);
  const hasPaper = prefs.wallpaperKind === "url" || prefs.wallpaperKind === "file";
  root.setAttribute("data-wallpaper", hasPaper ? "on" : "off");
}

function setWallpaperEl(src) {
  const el = document.getElementById("ah-wallpaper");
  if (!el) return;
  el.style.backgroundImage = src ? `url("${src}")` : "none";
}

export function applyWallpaper(prefs) {
  let src = "";
  if (prefs.wallpaperKind === "url" && /^https?:\/\//i.test(prefs.wallpaperUrl || prefs.wallpaperSrc || "")) {
    src = prefs.wallpaperSrc || prefs.wallpaperUrl;
  } else if (prefs.wallpaperKind === "file") {
    src = prefs.wallpaperSrc || "/api/settings/ui/wallpaper";
  }
  appliedSrc = src;
  setWallpaperEl(src);
}

export async function applyUi(prefs) {
  applyChrome(prefs);
  applyWallpaper(prefs);
  window.dispatchEvent(new CustomEvent("ah-ui-changed", { detail: prefs }));
  return prefs;
}

export function hexToHue(hex, fallback = DEFAULTS.accentHue) {
  const m = String(hex || "").trim().match(/^#?([0-9a-f]{6})$/i);
  if (!m) return fallback;
  const n = parseInt(m[1], 16);
  const r = ((n >> 16) & 255) / 255;
  const g = ((n >> 8) & 255) / 255;
  const b = (n & 255) / 255;
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  if (max - min < 0.08) return fallback;
  const d = max - min;
  let h = 0;
  if (max === r) h = ((g - b) / d + (g < b ? 6 : 0));
  else if (max === g) h = (b - r) / d + 2;
  else h = (r - g) / d + 4;
  return Math.round(h * 60) % 360;
}

export function hueToHex(h) {
  const hue = clampHue(h) / 360;
  const a = (p, q, t) => {
    if (t < 0) t += 1;
    if (t > 1) t -= 1;
    if (t < 1 / 6) return p + (q - p) * 6 * t;
    if (t < 1 / 2) return q;
    if (t < 2 / 3) return p + (q - p) * (2 / 3 - t) * 6;
    return p;
  };
  const q = 0.62;
  const p = 0.28;
  const r = Math.round(a(p, q, hue + 1 / 3) * 255);
  const g = Math.round(a(p, q, hue) * 255);
  const b = Math.round(a(p, q, hue - 1 / 3) * 255);
  return `#${[r, g, b].map((x) => x.toString(16).padStart(2, "0")).join("")}`;
}

export function compressImageFile(file, { maxEdge = 1920, quality = 0.72 } = {}) {
  return new Promise((resolve, reject) => {
    if (!file || !file.type?.startsWith("image/")) {
      reject(new Error("请选择图片文件"));
      return;
    }
    if (file.size > 12 * 1024 * 1024) {
      reject(new Error("图片太大，请选 12MB 以内"));
      return;
    }
    const img = new Image();
    const src = URL.createObjectURL(file);
    img.onload = () => {
      URL.revokeObjectURL(src);
      const scale = Math.min(1, maxEdge / Math.max(img.width, img.height));
      const w = Math.max(1, Math.round(img.width * scale));
      const h = Math.max(1, Math.round(img.height * scale));
      const canvas = document.createElement("canvas");
      canvas.width = w;
      canvas.height = h;
      const ctx = canvas.getContext("2d");
      ctx.drawImage(img, 0, 0, w, h);
      canvas.toBlob(
        (blob) => {
          if (!blob) {
            reject(new Error("图片压缩失败"));
            return;
          }
          if (blob.size > 3 * 1024 * 1024) {
            reject(new Error("压缩后仍超过 3MB，请换一张更小的图"));
            return;
          }
          resolve(blob);
        },
        "image/jpeg",
        quality,
      );
    };
    img.onerror = () => {
      URL.revokeObjectURL(src);
      reject(new Error("无法读取这张图片"));
    };
    img.src = src;
  });
}

export function resetUiLocal() {
  appliedSrc = "";
  return saveUiPrefs({ ...DEFAULTS });
}

export function markUiMigrated() {
  localStorage.setItem(MIGRATED_KEY, "1");
}

export function uiNeedsMigrate() {
  return localStorage.getItem(MIGRATED_KEY) !== "1";
}
