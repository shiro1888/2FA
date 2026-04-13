const DEFAULT_PERIOD = 30;
const DEFAULT_DIGITS = 6;
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const state = {
  secretBytes: null,
  lastCounter: null,
  lastCode: "",
  sessionId: 0,
  copyResetId: 0,
};

function sanitizeBase32(value) {
  return String(value ?? "")
    .trim()
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/=+$/g, "");
}

function extractSecret(value) {
  const trimmed = String(value ?? "").trim();

  if (!trimmed) {
    return "";
  }

  if (/^[A-Z2-7=\s-]+$/i.test(trimmed)) {
    return sanitizeBase32(trimmed);
  }

  try {
    const url = new URL(trimmed);
    const secret = url.searchParams.get("secret");
    return sanitizeBase32(secret);
  } catch {
    return sanitizeBase32(trimmed);
  }
}

function decodeBase32(secret) {
  const normalized = sanitizeBase32(secret);

  if (!normalized) {
    return new Uint8Array();
  }

  let value = 0;
  let bits = 0;
  const output = [];

  for (const char of normalized) {
    const index = BASE32_ALPHABET.indexOf(char);

    if (index === -1) {
      throw new Error("Setup Key 格式不正确，请输入 Base32 密钥。");
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
  const bytes = new Uint8Array(8);
  let value = BigInt(counter);

  for (let i = 7; i >= 0; i -= 1) {
    bytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }

  return bytes;
}

async function generateHotp(secretBytes, counter, digits = DEFAULT_DIGITS) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    secretBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign("HMAC", cryptoKey, counterToBytes(counter));
  const digest = new Uint8Array(signature);
  const offset = digest[digest.length - 1] & 0x0f;
  const code =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);

  return String(code % 10 ** digits).padStart(digits, "0");
}

function getCounter(timestamp = Date.now()) {
  return Math.floor(timestamp / 1000 / DEFAULT_PERIOD);
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

function clearError(elements) {
  elements.errorText.hidden = true;
  elements.errorText.textContent = "";
}

function showError(elements, message) {
  elements.resultPanel.hidden = true;
  elements.errorText.hidden = false;
  elements.errorText.textContent = message;
}

function renderIdle(elements) {
  clearError(elements);
  elements.resultPanel.hidden = true;
  elements.copyButton.disabled = true;
  document.title = "Google Authenticator 生成器";
}

function renderActive(elements, code, timestamp) {
  clearError(elements);
  elements.resultPanel.hidden = false;
  elements.copyButton.disabled = false;
  elements.codeOutput.textContent = code;

  const secondsRemaining = DEFAULT_PERIOD - Math.floor((timestamp / 1000) % DEFAULT_PERIOD);
  const fiveMinuteRemaining = 300 - Math.floor((timestamp / 1000) % 300);

  elements.countdownText.textContent = `距离刷新还有 ${secondsRemaining} 秒，5分钟倒计时：${fiveMinuteRemaining} 秒`;
  document.title = `${code} - Google Authenticator 生成器`;
}

function resetState() {
  state.secretBytes = null;
  state.lastCounter = null;
  state.lastCode = "";
  state.sessionId += 1;
}

function applyInput(elements) {
  const secret = extractSecret(elements.secretInput.value);

  if (!secret) {
    resetState();
    renderIdle(elements);
    return;
  }

  try {
    state.secretBytes = decodeBase32(secret);
    state.lastCounter = null;
    state.lastCode = "";
    state.sessionId += 1;
    void tick(elements, state.sessionId);
  } catch (error) {
    resetState();
    showError(elements, error.message);
  }
}

async function tick(elements, sessionId = state.sessionId) {
  if (!state.secretBytes?.length) {
    renderIdle(elements);
    return;
  }

  const now = Date.now();
  const counter = getCounter(now);

  if (counter !== state.lastCounter) {
    const code = await generateHotp(state.secretBytes, counter);

    if (sessionId !== state.sessionId) {
      return;
    }

    state.lastCounter = counter;
    state.lastCode = code;
  }

  renderActive(elements, state.lastCode, now);
}

function hydrateFromQuery(input) {
  const params = new URLSearchParams(window.location.search);
  const secret = params.get("secret");

  if (secret) {
    input.value = secret;
  }
}

function resetCopyButton(copyButton) {
  const currentResetId = ++state.copyResetId;

  window.setTimeout(() => {
    if (currentResetId === state.copyResetId) {
      copyButton.textContent = "复制验证码";
    }
  }, 1500);
}

function init() {
  const elements = {
    secretInput: document.querySelector("#secretInput"),
    clearButton: document.querySelector("#clearButton"),
    resultPanel: document.querySelector("#resultPanel"),
    codeOutput: document.querySelector("#codeOutput"),
    countdownText: document.querySelector("#countdownText"),
    copyButton: document.querySelector("#copyButton"),
    errorText: document.querySelector("#errorText"),
  };

  if (Object.values(elements).some((item) => item == null)) {
    return;
  }

  hydrateFromQuery(elements.secretInput);
  applyInput(elements);

  elements.secretInput.addEventListener("input", () => {
    applyInput(elements);
  });

  elements.clearButton.addEventListener("click", () => {
    elements.secretInput.value = "";
    resetState();
    renderIdle(elements);
    elements.secretInput.focus();
  });

  elements.copyButton.addEventListener("click", async () => {
    try {
      const copied = await copyText(state.lastCode);
      elements.copyButton.textContent = copied ? "已复制" : "复制失败";
    } catch {
      elements.copyButton.textContent = "复制失败";
    }

    resetCopyButton(elements.copyButton);
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
  }, 250);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init, { once: true });
} else {
  init();
}
