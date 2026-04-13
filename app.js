const DEFAULT_PROFILE = Object.freeze({
  digits: 6,
  period: 30,
  algorithm: "SHA-1",
});

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const state = {
  profile: null,
  secretBytes: null,
  lastCounter: null,
  lastCode: "",
  sessionId: 0,
  copyResetId: 0,
  qrSupportReady: false,
  qrSupported: false,
};

let qrDetectorPromise = null;

export function sanitizeBase32(value) {
  return String(value ?? "")
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/=+$/g, "");
}

function clampInteger(rawValue, fallback, min, max) {
  const parsed = Number.parseInt(String(rawValue ?? ""), 10);

  if (Number.isNaN(parsed)) {
    return fallback;
  }

  return Math.min(max, Math.max(min, parsed));
}

function normalizeAlgorithm(rawValue) {
  const compact = String(rawValue ?? "")
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "");

  if (compact === "SHA1") {
    return "SHA-1";
  }

  if (compact === "SHA256") {
    return "SHA-256";
  }

  if (compact === "SHA512") {
    return "SHA-512";
  }

  throw new Error("仅支持 SHA-1、SHA-256 或 SHA-512。");
}

function extractEmbeddedSecretValue(value) {
  try {
    const parsed = new URL(String(value ?? "").trim());
    const embeddedUri = parsed.searchParams.get("uri") || parsed.searchParams.get("otpauth");

    if (embeddedUri) {
      return embeddedUri.trim();
    }

    const embeddedSecret = parsed.searchParams.get("secret");

    if (embeddedSecret) {
      return embeddedSecret.trim();
    }
  } catch {
    return "";
  }

  return "";
}

function parseOtpAuthUri(uri) {
  let parsed;

  try {
    parsed = new URL(uri);
  } catch {
    throw new Error("otpauth 链接格式无效。");
  }

  if (parsed.protocol !== "otpauth:") {
    throw new Error("输入的链接不是 otpauth 协议。");
  }

  if (parsed.hostname.toLowerCase() !== "totp") {
    throw new Error("当前页面仅支持 TOTP 类型。");
  }

  const label = decodeURIComponent(parsed.pathname.replace(/^\/+/, ""));
  const secret = sanitizeBase32(parsed.searchParams.get("secret") ?? "");

  if (!secret) {
    throw new Error("otpauth 链接里缺少 secret 参数。");
  }

  let issuerFromLabel = "";
  let accountName = label;

  if (label.includes(":")) {
    const parts = label.split(/:(.+)/);
    issuerFromLabel = parts[0]?.trim() ?? "";
    accountName = parts[1]?.trim() ?? "";
  }

  return {
    secret,
    issuer: parsed.searchParams.get("issuer")?.trim() || issuerFromLabel,
    accountName,
    digits: clampInteger(parsed.searchParams.get("digits"), DEFAULT_PROFILE.digits, 4, 10),
    period: clampInteger(parsed.searchParams.get("period"), DEFAULT_PROFILE.period, 5, 300),
    algorithm: normalizeAlgorithm(parsed.searchParams.get("algorithm") || DEFAULT_PROFILE.algorithm),
    source: "otpauth",
  };
}

export function parseSecretInput(rawInput) {
  const trimmed = String(rawInput ?? "").trim();

  if (!trimmed) {
    return {
      ...DEFAULT_PROFILE,
      secret: "",
      issuer: "",
      accountName: "",
      source: "empty",
    };
  }

  if (trimmed.toLowerCase().startsWith("otpauth-migration://")) {
    throw new Error("暂不支持 otpauth-migration 二维码，请先导出为单个 otpauth://totp 链接。");
  }

  if (trimmed.toLowerCase().startsWith("otpauth://")) {
    return parseOtpAuthUri(trimmed);
  }

  const embeddedValue = extractEmbeddedSecretValue(trimmed);

  if (embeddedValue) {
    return parseSecretInput(embeddedValue);
  }

  return {
    ...DEFAULT_PROFILE,
    secret: sanitizeBase32(trimmed),
    issuer: "",
    accountName: "",
    source: "secret",
  };
}

export function decodeBase32(secret) {
  const normalized = sanitizeBase32(secret);

  if (!normalized) {
    return new Uint8Array();
  }

  let value = 0;
  let bits = 0;
  const output = [];

  for (const character of normalized) {
    const index = BASE32_ALPHABET.indexOf(character);

    if (index === -1) {
      throw new Error("Secret 必须是 Base32 格式，只能包含 A-Z 和 2-7。");
    }

    value = (value << 5) | index;
    bits += 5;

    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return new Uint8Array(output);
}

function counterToBytes(counter) {
  const result = new Uint8Array(8);
  let value = BigInt(counter);

  for (let index = 7; index >= 0; index -= 1) {
    result[index] = Number(value & 0xffn);
    value >>= 8n;
  }

  return result;
}

async function signCounter(secretBytes, counter, algorithm) {
  if (!globalThis.crypto?.subtle) {
    throw new Error("当前浏览器不支持 Web Crypto API。");
  }

  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    secretBytes,
    { name: "HMAC", hash: algorithm },
    false,
    ["sign"],
  );

  const signature = await globalThis.crypto.subtle.sign("HMAC", key, counterToBytes(counter));
  return new Uint8Array(signature);
}

export function getTotpCounter(timestamp = Date.now(), period = DEFAULT_PROFILE.period) {
  return Math.floor(timestamp / 1000 / period);
}

export async function generateHotp(
  secretBytes,
  counter,
  digits = DEFAULT_PROFILE.digits,
  algorithm = DEFAULT_PROFILE.algorithm,
) {
  const digest = await signCounter(secretBytes, counter, algorithm);
  const offset = digest[digest.length - 1] & 0x0f;

  // RFC 4226 dynamic truncation.
  const binaryCode =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);

  const otp = binaryCode % 10 ** digits;
  return String(otp).padStart(digits, "0");
}

export async function generateTotp(secret, options = {}) {
  const {
    digits = DEFAULT_PROFILE.digits,
    period = DEFAULT_PROFILE.period,
    algorithm = DEFAULT_PROFILE.algorithm,
    timestamp = Date.now(),
  } = options;

  const secretBytes = secret instanceof Uint8Array ? secret : decodeBase32(secret);
  const counter = getTotpCounter(timestamp, period);

  return generateHotp(secretBytes, counter, digits, algorithm);
}

function formatCode(code) {
  return code.replace(/(.{3})(?=.)/g, "$1 ");
}

function formatTime(timestamp) {
  return new Intl.DateTimeFormat("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(timestamp);
}

function resolveProfileTitle(profile) {
  if (profile.issuer && profile.accountName) {
    return `${profile.issuer} · ${profile.accountName}`;
  }

  if (profile.accountName) {
    return profile.accountName;
  }

  if (profile.issuer) {
    return profile.issuer;
  }

  return "标准 TOTP";
}

function normalizeImportedInput(rawValue) {
  const trimmed = String(rawValue ?? "").trim();

  if (!trimmed) {
    throw new Error("二维码内容为空。");
  }

  if (trimmed.toLowerCase().startsWith("otpauth-migration://")) {
    throw new Error("暂不支持 Google Authenticator 的批量迁移二维码。");
  }

  if (trimmed.toLowerCase().startsWith("otpauth://")) {
    return trimmed;
  }

  const embeddedValue = extractEmbeddedSecretValue(trimmed);

  if (embeddedValue) {
    return embeddedValue;
  }

  if (/^[a-z2-7=\s-]+$/i.test(trimmed)) {
    return sanitizeBase32(trimmed);
  }

  throw new Error("二维码内容不是可识别的 otpauth 链接或 Base32 Secret。");
}

async function copyText(value) {
  if (!value) {
    return false;
  }

  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return true;
  }

  const helper = document.createElement("textarea");
  helper.value = value;
  helper.setAttribute("readonly", "");
  helper.style.position = "fixed";
  helper.style.left = "-9999px";
  document.body.append(helper);
  helper.select();

  const copied = document.execCommand("copy");
  helper.remove();
  return copied;
}

function resetCopyButton(copyButton) {
  const resetId = ++state.copyResetId;

  window.setTimeout(() => {
    if (resetId === state.copyResetId) {
      copyButton.textContent = "复制验证码";
    }
  }, 1600);
}

function setUploadStatus(elements, message, tone = "neutral") {
  elements.uploadStatus.textContent = message;
  elements.uploadStatus.dataset.tone = tone;
}

function setUploadButtonState(elements, busy = false) {
  elements.uploadQrButton.disabled = busy || !state.qrSupported;
  elements.uploadQrButton.textContent = busy ? "识别中..." : "上传二维码识别";
}

async function getQrDetector() {
  if (qrDetectorPromise) {
    return qrDetectorPromise;
  }

  qrDetectorPromise = (async () => {
    if (!("BarcodeDetector" in globalThis)) {
      return null;
    }

    if (typeof globalThis.BarcodeDetector.getSupportedFormats === "function") {
      try {
        const formats = await globalThis.BarcodeDetector.getSupportedFormats();

        if (Array.isArray(formats) && !formats.includes("qr_code")) {
          return null;
        }
      } catch {
        // Ignore capability probe errors and try constructing the detector.
      }
    }

    try {
      return new globalThis.BarcodeDetector({ formats: ["qr_code"] });
    } catch {
      return null;
    }
  })();

  return qrDetectorPromise;
}

async function loadQrAsset(file) {
  if (typeof createImageBitmap === "function") {
    const bitmap = await createImageBitmap(file);
    return {
      image: bitmap,
      cleanup() {
        bitmap.close?.();
      },
    };
  }

  const objectUrl = URL.createObjectURL(file);
  const image = new Image();
  image.src = objectUrl;
  await image.decode();

  return {
    image,
    cleanup() {
      URL.revokeObjectURL(objectUrl);
    },
  };
}

async function detectQrTextFromFile(file) {
  const detector = await getQrDetector();

  if (!detector) {
    throw new Error("当前浏览器不支持二维码识别，请使用最新版 Chrome 或 Edge。");
  }

  const asset = await loadQrAsset(file);

  try {
    const results = await detector.detect(asset.image);
    const match = results.find((item) => typeof item.rawValue === "string" && item.rawValue.trim());

    if (!match) {
      throw new Error("未识别到二维码，请上传清晰、完整、正向的二维码图片。");
    }

    return match.rawValue.trim();
  } finally {
    asset.cleanup();
  }
}

async function syncQrCapability(elements) {
  const detector = await getQrDetector();
  state.qrSupported = Boolean(detector);
  state.qrSupportReady = true;

  if (state.qrSupported) {
    setUploadStatus(
      elements,
      "上传二维码图片后，自动提取其中的 otpauth 链接或 Base32 Secret。",
      "neutral",
    );
  } else {
    setUploadStatus(
      elements,
      "当前浏览器不支持二维码识别，建议使用最新版 Chrome 或 Edge，或手动粘贴 secret。",
      "warning",
    );
  }

  setUploadButtonState(elements, false);
}

function clearError(elements) {
  elements.errorText.hidden = true;
  elements.errorText.textContent = "";
}

function showError(elements, message) {
  elements.errorText.hidden = false;
  elements.errorText.textContent = message;
}

function renderIdle(elements) {
  clearError(elements);
  elements.profileName.textContent = "等待输入 Secret";
  elements.profileMeta.textContent =
    "支持 Base32 Secret、otpauth://totp 链接与二维码上传识别，所有计算都在当前浏览器完成。";
  elements.codeOutput.textContent = "--- ---";
  elements.codeOutput.classList.remove("is-refreshing");
  elements.progressBar.style.transform = "scaleX(1)";
  elements.countdownText.innerHTML =
    "可通过 <code>?secret=YOUR_BASE32_SECRET</code> 方式直接预填。";
  elements.copyButton.disabled = true;
  elements.sourceHint.textContent = "支持粘贴 otpauth://totp/... 或上传二维码";
  document.title = "2FA TOTP Generator";
}

function renderInvalid(elements, message) {
  state.lastCode = "";
  clearError(elements);
  showError(elements, message);
  elements.profileName.textContent = "输入有误";
  elements.profileMeta.textContent = "请检查 Secret 是否是 Base32，或确认 otpauth 链接格式完整。";
  elements.codeOutput.textContent = "--- ---";
  elements.codeOutput.classList.remove("is-refreshing");
  elements.progressBar.style.transform = "scaleX(0)";
  elements.countdownText.textContent = "修正输入后会立即重新计算验证码。";
  elements.copyButton.disabled = true;
  elements.sourceHint.textContent = "等待有效输入";
  document.title = "2FA TOTP Generator";
}

function renderActive(elements, profile, code, now, isNewCode) {
  clearError(elements);

  const exactRemaining = profile.period - ((now / 1000) % profile.period);
  const nextRefreshAt = (getTotpCounter(now, profile.period) + 1) * profile.period * 1000;

  elements.profileName.textContent = resolveProfileTitle(profile);
  elements.profileMeta.textContent = `${profile.digits} 位验证码 · ${profile.period} 秒周期 · ${profile.algorithm}`;
  elements.codeOutput.textContent = formatCode(code);
  elements.progressBar.style.transform = `scaleX(${exactRemaining / profile.period})`;
  elements.countdownText.textContent = `距离下一次刷新还有 ${Math.ceil(exactRemaining)} 秒，下一次更新时间 ${formatTime(nextRefreshAt)}。`;
  elements.copyButton.disabled = false;
  elements.sourceHint.textContent =
    profile.source === "otpauth" ? "已识别 otpauth:// 链接" : "已识别 Base32 Secret";

  if (isNewCode) {
    elements.codeOutput.classList.remove("is-refreshing");
    void elements.codeOutput.offsetWidth;
    elements.codeOutput.classList.add("is-refreshing");
  }

  document.title = `${code} · 2FA`;
}

function clearState() {
  state.profile = null;
  state.secretBytes = null;
  state.lastCounter = null;
  state.lastCode = "";
  state.sessionId += 1;
}

function handleSecretChange(elements) {
  const rawValue = elements.secretInput.value;

  if (!rawValue.trim()) {
    clearState();
    renderIdle(elements);
    return;
  }

  try {
    const profile = parseSecretInput(rawValue);
    const secretBytes = decodeBase32(profile.secret);

    state.profile = profile;
    state.secretBytes = secretBytes;
    state.lastCounter = null;
    state.lastCode = "";
    state.sessionId += 1;

    clearError(elements);
    void tick(elements, state.sessionId);
  } catch (error) {
    clearState();
    renderInvalid(elements, error.message);
  }
}

async function handleQrUpload(elements, file) {
  if (!file) {
    return;
  }

  setUploadButtonState(elements, true);
  setUploadStatus(elements, `正在识别 ${file.name} ...`, "neutral");

  try {
    const rawValue = await detectQrTextFromFile(file);
    const normalizedInput = normalizeImportedInput(rawValue);

    // Validate before replacing the user's current input.
    parseSecretInput(normalizedInput);

    elements.secretInput.value = normalizedInput;
    handleSecretChange(elements);

    setUploadStatus(
      elements,
      normalizedInput.toLowerCase().startsWith("otpauth://")
        ? "二维码识别成功，已提取 otpauth 链接。"
        : "二维码识别成功，已提取 Base32 Secret。",
      "success",
    );
  } catch (error) {
    setUploadStatus(elements, error.message, "error");
  } finally {
    setUploadButtonState(elements, false);
    elements.qrFileInput.value = "";
  }
}

async function tick(elements, sessionId = state.sessionId) {
  if (!state.profile || !state.secretBytes?.length) {
    renderIdle(elements);
    return;
  }

  const now = Date.now();
  const counter = getTotpCounter(now, state.profile.period);
  let isNewCode = false;

  if (counter !== state.lastCounter) {
    const nextCode = await generateHotp(
      state.secretBytes,
      counter,
      state.profile.digits,
      state.profile.algorithm,
    );

    if (sessionId !== state.sessionId) {
      return;
    }

    state.lastCounter = counter;
    state.lastCode = nextCode;
    isNewCode = true;
  }

  renderActive(elements, state.profile, state.lastCode, now, isNewCode);
}

function hydrateFromQuery(secretInput) {
  const params = new URLSearchParams(window.location.search);
  const uriPrefill = params.get("uri") || params.get("otpauth");
  const secretPrefill = params.get("secret");

  if (uriPrefill) {
    secretInput.value = uriPrefill;
    return;
  }

  if (secretPrefill) {
    secretInput.value = secretPrefill;
  }
}

function init() {
  const elements = {
    secretInput: document.querySelector("#secretInput"),
    clearButton: document.querySelector("#clearButton"),
    copyButton: document.querySelector("#copyButton"),
    uploadQrButton: document.querySelector("#uploadQrButton"),
    qrFileInput: document.querySelector("#qrFileInput"),
    uploadStatus: document.querySelector("#uploadStatus"),
    profileName: document.querySelector("#profileName"),
    profileMeta: document.querySelector("#profileMeta"),
    codeOutput: document.querySelector("#codeOutput"),
    progressBar: document.querySelector("#progressBar"),
    countdownText: document.querySelector("#countdownText"),
    errorText: document.querySelector("#errorText"),
    sourceHint: document.querySelector("#sourceHint"),
  };

  if (Object.values(elements).some((value) => value == null)) {
    return;
  }

  hydrateFromQuery(elements.secretInput);
  handleSecretChange(elements);
  setUploadStatus(elements, "正在检查浏览器二维码识别能力...", "neutral");
  elements.uploadQrButton.disabled = true;
  void syncQrCapability(elements);

  elements.secretInput.addEventListener("input", () => {
    handleSecretChange(elements);
  });

  elements.uploadQrButton.addEventListener("click", () => {
    if (state.qrSupported) {
      elements.qrFileInput.click();
    }
  });

  elements.qrFileInput.addEventListener("change", () => {
    const file = elements.qrFileInput.files?.[0];
    void handleQrUpload(elements, file);
  });

  elements.clearButton.addEventListener("click", () => {
    elements.secretInput.value = "";
    clearState();
    renderIdle(elements);
    elements.secretInput.focus();
  });

  elements.copyButton.addEventListener("click", async () => {
    try {
      const copied = await copyText(state.lastCode);

      if (!copied) {
        throw new Error("复制失败");
      }

      elements.copyButton.textContent = "已复制";
      resetCopyButton(elements.copyButton);
    } catch {
      elements.copyButton.textContent = "复制失败";
      resetCopyButton(elements.copyButton);
    }
  });

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      void tick(elements);
    }
  });

  window.addEventListener("focus", () => {
    void tick(elements);
  });

  window.setInterval(() => {
    void tick(elements);
  }, 200);
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
}
