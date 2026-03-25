/* ============================================================
   CipherLab — app.js
   Dynamic encrypt / decrypt with 6 cipher algorithms.
   All processing is client-side only.
   ============================================================ */

// ─── State ───────────────────────────────────────────────────
let mode   = 'encrypt';   // 'encrypt' | 'decrypt'
let cipher = 'caesar';

// ─── DOM refs ────────────────────────────────────────────────
const inputText      = document.getElementById('inputText');
const outputText     = document.getElementById('outputText');
const cipherSelect   = document.getElementById('cipherSelect');
const caesarKey      = document.getElementById('caesarKey');
const vigenereKey    = document.getElementById('vigenereKey');
const xorKey         = document.getElementById('xorKey');
const noKeyBadge     = document.getElementById('noKeyBadge');
const keyLabel       = document.getElementById('keyLabel');
const encryptBtn     = document.getElementById('encryptBtn');
const decryptBtn     = document.getElementById('decryptBtn');
const clearBtn       = document.getElementById('clearBtn');
const copyBtn        = document.getElementById('copyBtn');
const swapBtn        = document.getElementById('swapBtn');
const themeToggle    = document.getElementById('themeToggle');
const inputCharCount  = document.getElementById('inputCharCount');
const inputWordCount  = document.getElementById('inputWordCount');
const outputCharCount = document.getElementById('outputCharCount');
const outputWordCount = document.getElementById('outputWordCount');
const inputTitle     = document.getElementById('inputTitle');
const outputTitle    = document.getElementById('outputTitle');
const processIndicator = document.getElementById('processIndicator');
const cipherInfoEl   = document.getElementById('cipherInfo');
const outputPanel    = document.querySelector('.panel-output');

// ─── Cipher info descriptions ─────────────────────────────────
const CIPHER_INFO = {
  caesar:   'Caesar Cipher shifts each letter by a fixed number (1–25) through the alphabet. Non-alphabetic characters are preserved as-is.',
  vigenere: 'Vigenère Cipher uses a keyword to apply multiple Caesar shifts. Each letter of the key shifts the corresponding plaintext letter.',
  rot13:    'ROT13 rotates each letter by 13 positions. Applying it twice returns the original text — the same operation encrypts and decrypts.',
  base64:   'Base64 encodes binary/text data as ASCII characters using 64 printable symbols. It is an encoding scheme, not a security cipher.',
  xor:      'XOR Cipher applies bitwise XOR between each byte of the message and a repeating hex key. Symmetric — the same key encrypts and decrypts.',
  atbash:   'Atbash Cipher maps A↔Z, B↔Y, etc. It is its own inverse — decrypting with Atbash uses the same operation as encrypting.',
};

// ─── Cipher implementations ───────────────────────────────────

/** Rotate a single character within its case range by `shift`. */
function rotChar(ch, shift) {
  const base = ch >= 'a' ? 97 : 65;
  return String.fromCharCode(((ch.charCodeAt(0) - base + shift + 26) % 26) + base);
}

function caesarEncrypt(text, shift) {
  return [...text].map(ch => /[a-zA-Z]/.test(ch) ? rotChar(ch, shift) : ch).join('');
}

function caesarDecrypt(text, shift) {
  return caesarEncrypt(text, 26 - (shift % 26));
}

function vigenereEncrypt(text, key) {
  if (!key) return text;
  const k = key.toUpperCase().replace(/[^A-Z]/g, '');
  if (!k.length) return text;
  let ki = 0;
  return [...text].map(ch => {
    if (/[a-zA-Z]/.test(ch)) {
      const shift = k.charCodeAt(ki % k.length) - 65;
      ki++;
      return rotChar(ch, shift);
    }
    return ch;
  }).join('');
}

function vigenereDecrypt(text, key) {
  if (!key) return text;
  const k = key.toUpperCase().replace(/[^A-Z]/g, '');
  if (!k.length) return text;
  let ki = 0;
  return [...text].map(ch => {
    if (/[a-zA-Z]/.test(ch)) {
      const shift = k.charCodeAt(ki % k.length) - 65;
      ki++;
      return rotChar(ch, 26 - shift);
    }
    return ch;
  }).join('');
}

function rot13(text) {
  return caesarEncrypt(text, 13);
}

function base64Encode(text) {
  try { return btoa(unescape(encodeURIComponent(text))); }
  catch { return ''; }
}

function base64Decode(text) {
  try { return decodeURIComponent(escape(atob(text.trim()))); }
  catch { return null; } // signals invalid input
}

function xorCipher(text, hexKey) {
  const cleaned = hexKey.replace(/\s/g, '');
  if (!cleaned || cleaned.length % 2 !== 0) return text;
  const bytes = [];
  for (let i = 0; i < cleaned.length; i += 2) {
    bytes.push(parseInt(cleaned.substr(i, 2), 16));
  }
  if (bytes.some(isNaN)) return text;
  return [...text].map((ch, i) => {
    return String.fromCharCode(ch.charCodeAt(0) ^ bytes[i % bytes.length]);
  }).join('');
}

function atbash(text) {
  return [...text].map(ch => {
    if (/[a-z]/.test(ch)) return String.fromCharCode(219 - ch.charCodeAt(0)); // 'a'+('z'-ch)
    if (/[A-Z]/.test(ch)) return String.fromCharCode(155 - ch.charCodeAt(0)); // 'A'+('Z'-ch)
    return ch;
  }).join('');
}

// ─── Core process function ────────────────────────────────────
function process() {
  const text = inputText.value;
  let result = '';
  let isError = false;

  const shift    = Math.max(1, Math.min(25, parseInt(caesarKey.value) || 1));
  const vigKey   = vigenereKey.value;
  const xorK     = xorKey.value;

  switch (cipher) {
    case 'caesar':
      result = mode === 'encrypt' ? caesarEncrypt(text, shift) : caesarDecrypt(text, shift);
      break;
    case 'vigenere':
      result = mode === 'encrypt' ? vigenereEncrypt(text, vigKey) : vigenereDecrypt(text, vigKey);
      break;
    case 'rot13':
      result = rot13(text); // symmetric
      break;
    case 'base64':
      if (mode === 'encrypt') {
        result = base64Encode(text);
      } else {
        const decoded = base64Decode(text);
        if (decoded === null) { result = '⚠ Invalid Base64 input'; isError = true; }
        else result = decoded;
      }
      break;
    case 'xor':
      result = xorCipher(text, xorK); // symmetric
      break;
    case 'atbash':
      result = atbash(text); // symmetric
      break;
  }

  outputText.value = result;

  // Flash output
  outputPanel.classList.remove('output-flash', 'error');
  void outputPanel.offsetWidth; // reflow
  if (isError) outputPanel.classList.add('error');
  else         outputPanel.classList.add('output-flash');

  // Counts
  updateCounts(text, result);

  // Indicator
  processIndicator.classList.toggle('active', text.length > 0);
}

// ─── Count helpers ────────────────────────────────────────────
function wordCount(str) {
  return str.trim() ? str.trim().split(/\s+/).length : 0;
}

function updateCounts(input, output) {
  inputCharCount.textContent  = input.length;
  inputWordCount.textContent  = wordCount(input);
  outputCharCount.textContent = output.length;
  outputWordCount.textContent = wordCount(output);
}

// ─── Mode toggle ─────────────────────────────────────────────
function setMode(m) {
  mode = m;
  encryptBtn.classList.toggle('active', m === 'encrypt');
  decryptBtn.classList.toggle('active', m === 'decrypt');
  inputTitle.textContent  = m === 'encrypt' ? 'Plaintext'  : 'Ciphertext';
  outputTitle.textContent = m === 'encrypt' ? 'Ciphertext' : 'Plaintext';
  process();
}

// ─── Cipher select ────────────────────────────────────────────
function updateKeyUI() {
  // Hide all key inputs
  caesarKey.classList.add('hidden');
  vigenereKey.classList.add('hidden');
  xorKey.classList.add('hidden');
  noKeyBadge.classList.add('hidden');

  switch (cipher) {
    case 'caesar':
      caesarKey.classList.remove('hidden');
      keyLabel.textContent = 'Shift (1–25)';
      break;
    case 'vigenere':
      vigenereKey.classList.remove('hidden');
      keyLabel.textContent = 'Keyword';
      break;
    case 'xor':
      xorKey.classList.remove('hidden');
      keyLabel.textContent = 'Hex Key';
      break;
    default:
      noKeyBadge.classList.remove('hidden');
      keyLabel.textContent = 'Key';
  }

  cipherInfoEl.textContent = CIPHER_INFO[cipher] || '';
}

// ─── Theme color meta sync ────────────────────────────────────
function syncThemeColor() {
  const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
  const meta = document.getElementById('themeColor');
  if (meta) meta.setAttribute('content', isDark ? '#0f1117' : '#f0f2f8');
}

// ─── Theme toggle ─────────────────────────────────────────────
function toggleTheme() {
  const html = document.documentElement;
  const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  localStorage.setItem('cipherlab-theme', next);
  syncThemeColor();
}

// ─── Swap ─────────────────────────────────────────────────────
function swap() {
  const tmp = inputText.value;
  inputText.value = outputText.value;
  outputText.value = '';
  process();
  inputText.focus();
}

// ─── Copy ─────────────────────────────────────────────────────
async function copyToClipboard() {
  const txt = outputText.value;
  if (!txt) return;
  try {
    await navigator.clipboard.writeText(txt);
    const copyLabel = document.getElementById('copyLabel');
    copyBtn.classList.add('success');
    copyLabel.textContent = 'Copied!';
    setTimeout(() => {
      copyBtn.classList.remove('success');
      copyLabel.textContent = 'Copy';
    }, 2000);
  } catch {
    // Fallback
    outputText.select();
    document.execCommand('copy');
  }
}

// ─── Event Listeners ─────────────────────────────────────────
inputText.addEventListener('input', process);

cipherSelect.addEventListener('change', () => {
  cipher = cipherSelect.value;
  updateKeyUI();
  process();
});

caesarKey.addEventListener('input', process);
vigenereKey.addEventListener('input', process);
xorKey.addEventListener('input', process);

encryptBtn.addEventListener('click', () => setMode('encrypt'));
decryptBtn.addEventListener('click', () => setMode('decrypt'));

clearBtn.addEventListener('click', () => {
  inputText.value = '';
  outputText.value = '';
  updateCounts('', '');
  processIndicator.classList.remove('active');
  inputText.focus();
});

copyBtn.addEventListener('click', copyToClipboard);
swapBtn.addEventListener('click', swap);
themeToggle.addEventListener('click', toggleTheme);

// ─── Mobile Nav ──────────────────────────────────────────────
const mobileNav    = document.getElementById('mobileNav');
const navEncrypt   = document.getElementById('navEncrypt');
const navDecrypt   = document.getElementById('navDecrypt');
const navSwap      = document.getElementById('navSwap');
const navCopy      = document.getElementById('navCopy');

function syncMobileNav() {
  navEncrypt.classList.toggle('active', mode === 'encrypt');
  navDecrypt.classList.toggle('active', mode === 'decrypt');
}

navEncrypt.addEventListener('click', () => { setMode('encrypt'); syncMobileNav(); });
navDecrypt.addEventListener('click', () => { setMode('decrypt'); syncMobileNav(); });
navSwap.addEventListener('click', swap);
navCopy.addEventListener('click', async () => {
  await copyToClipboard();
  navCopy.classList.add('copied');
  setTimeout(() => navCopy.classList.remove('copied'), 2000);
});

// ─── PWA Install Prompt ───────────────────────────────────────
let deferredInstallPrompt = null;
const installBanner    = document.getElementById('installBanner');
const installBtn       = document.getElementById('installBtn');
const dismissBtn       = document.getElementById('dismissInstall');
const installHeaderBtn = document.getElementById('installHeaderBtn');

async function triggerInstall() {
  if (!deferredInstallPrompt) return;
  deferredInstallPrompt.prompt();
  const { outcome } = await deferredInstallPrompt.userChoice;
  if (outcome === 'accepted') hideInstallUI();
  deferredInstallPrompt = null;
}

function hideInstallUI() {
  installBanner.classList.remove('visible');
  installHeaderBtn.classList.add('hidden');
}

window.addEventListener('beforeinstallprompt', e => {
  e.preventDefault();
  deferredInstallPrompt = e;
  installBanner.classList.add('visible');   // always show banner
  installHeaderBtn.classList.remove('hidden'); // always show header btn
});

installBtn.addEventListener('click', triggerInstall);
installHeaderBtn.addEventListener('click', triggerInstall);

dismissBtn.addEventListener('click', () => {
  // Only hides the banner — header button stays visible
  installBanner.classList.remove('visible');
});

window.addEventListener('appinstalled', hideInstallUI);

// ─── Service Worker ───────────────────────────────────────────
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  });
}

// ─── Init ─────────────────────────────────────────────────────
(function init() {
  // Restore saved theme
  const saved = localStorage.getItem('cipherlab-theme');
  if (saved) document.documentElement.setAttribute('data-theme', saved);

  cipher = cipherSelect.value;
  updateKeyUI();
  process();
  syncMobileNav();
  syncThemeColor();
})();
