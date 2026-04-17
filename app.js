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
  caesar:   'Caesar Cipher shifts each character within its script. Supports Latin (26), Hiragana/Katakana (86), and Kanji (20,992 chars). Non-script characters pass through unchanged.',
  vigenere: 'Vigenere cipher uses a keyword for per-character shifts. Supports Latin, Hiragana, Katakana, and Kanji. The key can mix scripts.',
  rot13:    'ROT13/ROT43 — rotates Latin letters by 13 (half of 26) and Japanese Hiragana/Katakana by 43 (half of 86). Symmetric: encrypt and decrypt apply the same transform. Applying it twice always restores the original.',
  base64:   'Base64 encodes binary/text data as ASCII characters using 64 printable symbols. Fully supports Unicode including Japanese. It is an encoding scheme, not a security cipher.',
  xor:      'XOR Cipher applies bitwise XOR between each character code and a repeating hex key. Symmetric — the same key encrypts and decrypts. Works with any Unicode text.',
  atbash:   'Atbash mirrors each character within its script range (A↔Z, あ↔ん, ア↔ン, etc.). Symmetric: the same operation encrypts and decrypts — any input is valid in both modes.',
};

// ─── Cipher implementations ───────────────────────────────────

// Script ranges
const LATIN_LOWER  = [97,  122];   // a-z  (26 chars)
const LATIN_UPPER  = [65,   90];   // A-Z  (26 chars)
const HIRAGANA     = [0x3041, 0x3096]; // ぁ-ゖ (86 chars)
const KATAKANA     = [0x30A1, 0x30F6]; // ァ-ヶ (86 chars)
const CJK          = [0x4E00, 0x9FFF]; // 一-鿿 (20,992 chars — all common kanji)

const RANGES = [LATIN_LOWER, LATIN_UPPER, HIRAGANA, KATAKANA, CJK];

/** Return [base, size] for a character's script range, or null if not rotatable. */
function scriptRange(ch) {
  const c = ch.charCodeAt(0);
  for (const [start, end] of RANGES) {
    if (c >= start && c <= end) return [start, end - start + 1];
  }
  return null;
}

/** Rotate ch by shift within its script range. Handles negative shifts. */
function rotChar(ch, shift) {
  const range = scriptRange(ch);
  if (!range) return ch;
  const [base, size] = range;
  return String.fromCharCode(((ch.charCodeAt(0) - base + shift % size + size) % size) + base);
}

/** Shift value contributed by a key character (0-based within its script). */
function keyShift(ch) {
  const c = ch.charCodeAt(0);
  for (const [start, end] of RANGES) {
    if (c >= start && c <= end) return c - start;
  }
  return 0;
}

function caesarEncrypt(text, shift) {
  return [...text].map(ch => scriptRange(ch) ? rotChar(ch, shift) : ch).join('');
}

function caesarDecrypt(text, shift) {
  return caesarEncrypt(text, -shift);
}

function vigenereEncrypt(text, key) {
  if (!key) return text;
  const keyChars = [...key].filter(ch => scriptRange(ch));
  if (!keyChars.length) return text;
  let ki = 0;
  return [...text].map(ch => {
    if (scriptRange(ch)) {
      const shift = keyShift(keyChars[ki % keyChars.length]);
      ki++;
      return rotChar(ch, shift);
    }
    return ch;
  }).join('');
}

function vigenereDecrypt(text, key) {
  if (!key) return text;
  const keyChars = [...key].filter(ch => scriptRange(ch));
  if (!keyChars.length) return text;
  let ki = 0;
  return [...text].map(ch => {
    if (scriptRange(ch)) {
      const shift = keyShift(keyChars[ki % keyChars.length]);
      ki++;
      return rotChar(ch, -shift);
    }
    return ch;
  }).join('');
}

/** ROT13 for Latin (half of 26), ROT43 for Hiragana/Katakana (half of 86). Both self-inverse. */
function rot13(text) {
  return [...text].map(ch => {
    const range = scriptRange(ch);
    if (!range) return ch;
    return rotChar(ch, range[1] / 2);
  }).join('');
}

function base64Encode(text) {
  try {
    const bytes = new TextEncoder().encode(text);
    return btoa(String.fromCharCode(...bytes));
  } catch { return ''; }
}

function base64Decode(text) {
  try {
    const bytes = Uint8Array.from(atob(text.trim()), c => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch { return null; } // signals invalid input
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
    const range = scriptRange(ch);
    if (!range) return ch;
    const [base, size] = range;
    // mirror: base + (size-1) - (ch - base)  =  base + size - 1 - ch + base
    return String.fromCharCode(2 * base + size - 1 - ch.charCodeAt(0));
  }).join('');
}

// ─── Playfair ─────────────────────────────────────────────────
function playfairBuildGrid(key) {
  const seen = new Set();
  const grid = [];
  const clean = (key.toUpperCase() + 'ABCDEFGHIKLMNOPQRSTUVWXYZ').replace(/[^A-Z]/g, '');
  for (const ch of clean) {
    const c = ch === 'J' ? 'I' : ch;
    if (!seen.has(c)) { seen.add(c); grid.push(c); }
  }
  return grid; // 25 chars, 5×5
}

function playfairPos(grid, ch) {
  const idx = grid.indexOf(ch === 'J' ? 'I' : ch);
  return [Math.floor(idx / 5), idx % 5];
}

function playfairProcess(text, key, encrypt) {
  const grid = playfairBuildGrid(key || 'KEY');
  const dir = encrypt ? 1 : -1;
  // Extract latin letters only; track original case; collect non-latin for append
  const positions = []; // non-latin chars from original text
  const letters = [];   // uppercase A-Z (J→I)
  const letterIsLower = []; // parallel: was the original char lowercase?
  for (const ch of text) {
    if (/[A-Za-z]/.test(ch)) {
      const up = ch.toUpperCase();
      letters.push(up === 'J' ? 'I' : up);
      letterIsLower.push(ch >= 'a' && ch <= 'z');
    } else {
      positions.push(ch);
    }
  }
  // Pad bigrams; track case for each output slot (null = padding char)
  const bigrams = [];
  const outputCase = []; // parallel to result array; true=lowercase, false=upper, null=padding
  let i = 0;
  while (i < letters.length) {
    const a = letters[i];
    const b = letters[i + 1];
    if (b === undefined) {
      bigrams.push([a, 'X']); outputCase.push(letterIsLower[i], null); i++;
    } else if (a === b) {
      bigrams.push([a, 'X']); outputCase.push(letterIsLower[i], null); i++;
    } else {
      bigrams.push([a, b]); outputCase.push(letterIsLower[i], letterIsLower[i + 1]); i += 2;
    }
  }
  // Encipher bigrams
  const result = [];
  for (const [a, b] of bigrams) {
    const [ar, ac] = playfairPos(grid, a);
    const [br, bc] = playfairPos(grid, b);
    let ca, cb;
    if (ar === br) {
      ca = grid[ar * 5 + ((ac + dir + 5) % 5)];
      cb = grid[br * 5 + ((bc + dir + 5) % 5)];
    } else if (ac === bc) {
      ca = grid[((ar + dir + 5) % 5) * 5 + ac];
      cb = grid[((br + dir + 5) % 5) * 5 + bc];
    } else {
      ca = grid[ar * 5 + bc];
      cb = grid[br * 5 + ac];
    }
    result.push(ca, cb);
  }
  // Restore original case; non-latin chars appended (padding shifts indices)
  const latinOut = result.map((ch, idx) => outputCase[idx] ? ch.toLowerCase() : ch);
  return latinOut.join('') + positions.join('');
}

function playfairEncrypt(text, key) { return playfairProcess(text, key, true); }
function playfairDecrypt(text, key) { return playfairProcess(text, key, false); }

// ─── Rail Fence ───────────────────────────────────────────────
function railFenceEncrypt(text, rails) {
  rails = Math.max(2, Math.min(10, rails));
  if (rails >= text.length) return text;
  const fence = Array.from({ length: rails }, () => []);
  let rail = 0, dir = 1;
  for (const ch of text) {
    fence[rail].push(ch);
    if (rail === 0) dir = 1;
    else if (rail === rails - 1) dir = -1;
    rail += dir;
  }
  return fence.flat().join('');
}

function railFenceDecrypt(text, rails) {
  rails = Math.max(2, Math.min(10, rails));
  const chars = [...text]; // code-point array — handles non-BMP Unicode
  if (rails >= chars.length) return text;
  const len = chars.length;
  const indices = new Array(len);
  let rail = 0, dir = 1;
  for (let i = 0; i < len; i++) {
    indices[i] = rail;
    if (rail === 0) dir = 1;
    else if (rail === rails - 1) dir = -1;
    rail += dir;
  }
  // Count chars per rail
  const counts = new Array(rails).fill(0);
  for (const r of indices) counts[r]++;
  // Slice chars array into rail rows
  const rows = [];
  let pos = 0;
  for (const c of counts) { rows.push(chars.slice(pos, pos + c)); pos += c; }
  // Read off by original order
  const rowIdx = new Array(rails).fill(0);
  return indices.map(r => rows[r][rowIdx[r]++]).join('');
}

// ─── Columnar Transposition ───────────────────────────────────
function columnarEncrypt(text, key) {
  const k = (key || '').replace(/[^a-zA-Z]/g, '').toUpperCase();
  if (!k) return text;
  const cols = k.length;
  const codePoints = [...text]; // handle non-BMP Unicode
  const rows = Math.ceil(codePoints.length / cols);
  // Pad with null char to fill grid
  const padded = [...codePoints, ...Array(rows * cols - codePoints.length).fill('\0')];
  // Build columns
  const grid = [];
  for (let c = 0; c < cols; c++) {
    const col = [];
    for (let r = 0; r < rows; r++) col.push(padded[r * cols + c]);
    grid.push({ char: k[c], col, origIdx: c });
  }
  // Sort by key character, stable (preserve original order for ties)
  grid.sort((a, b) => a.char < b.char ? -1 : a.char > b.char ? 1 : a.origIdx - b.origIdx);
  return grid.flatMap(g => g.col).filter(c => c !== '\0').join('');
}

function columnarDecrypt(text, key) {
  const k = (key || '').replace(/[^a-zA-Z]/g, '').toUpperCase();
  if (!k) return text;
  const cols = k.length;
  const codePoints = [...text]; // handle non-BMP Unicode
  const rows = Math.ceil(codePoints.length / cols);
  const totalCells = rows * cols;
  const shortCols = totalCells - codePoints.length; // columns with rows-1 chars
  // Build sorted order
  const order = [...k].map((char, origIdx) => ({ char, origIdx }));
  order.sort((a, b) => a.char < b.char ? -1 : a.char > b.char ? 1 : a.origIdx - b.origIdx);
  // Assign lengths by original column index (last shortCols original columns are short)
  const lengths = new Array(cols);
  for (let i = 0; i < cols; i++) {
    lengths[order[i].origIdx] = (order[i].origIdx >= cols - shortCols) ? rows - 1 : rows;
  }
  // Slice code-point array into sorted columns
  const sortedCols = [];
  let pos = 0;
  for (const { origIdx } of order) {
    const len = lengths[origIdx];
    sortedCols.push({ origIdx, chars: codePoints.slice(pos, pos + len) });
    pos += len;
  }
  // Reorder back to original column positions
  const cols2 = new Array(cols);
  for (const { origIdx, chars } of sortedCols) cols2[origIdx] = chars;
  // Read row by row
  const result = [];
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      if (cols2[c][r] !== undefined) result.push(cols2[c][r]);
    }
  }
  return result.join('');
}

// ─── Beaufort ─────────────────────────────────────────────────
function beaufort(text, key) {
  if (!key) return text;
  const keyChars = [...key].filter(ch => /[A-Za-z]/.test(ch));
  if (!keyChars.length) return text;
  let ki = 0;
  return [...text].map(ch => {
    if (/[A-Za-z]/.test(ch)) {
      const isUpper = ch === ch.toUpperCase();
      const base = isUpper ? 65 : 97;
      const kBase = keyChars[ki % keyChars.length].toUpperCase().charCodeAt(0) - 65;
      ki++;
      return String.fromCharCode(((kBase - (ch.toUpperCase().charCodeAt(0) - 65) + 26) % 26) + base);
    }
    return ch;
  }).join('');
}

// ─── AES-256-GCM ─────────────────────────────────────────────
async function aesEncrypt(text, password) {
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error('NO_SECURE_CONTEXT');
  }
  if (!text || !password) {
    throw new Error('INVALID_INPUT');
  }
  const enc = new TextEncoder();
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv   = window.crypto.getRandomValues(new Uint8Array(12));
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  const key = await window.crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const cipherBuf = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    enc.encode(text)
  );
  // Output: base64(salt[16] || iv[12] || ciphertext+tag[16])
  const combined = new Uint8Array(salt.length + iv.length + cipherBuf.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(cipherBuf), salt.length + iv.length);
  let binary = '';
  combined.forEach(b => { binary += String.fromCharCode(b); });
  return btoa(binary);
}

async function aesDecrypt(b64, password) {
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error('NO_SECURE_CONTEXT');
  }
  if (!b64 || !password) {
    throw new Error('INVALID_INPUT');
  }
  let bytes;
  try {
    bytes = Uint8Array.from(atob(b64.trim()), c => c.charCodeAt(0));
  } catch {
    throw new Error('INVALID_INPUT');
  }
  if (bytes.length < 28 + 16) { // salt(16) + iv(12) + tag(16) minimum
    throw new Error('INVALID_INPUT');
  }
  const salt = bytes.slice(0, 16);
  const iv   = bytes.slice(16, 28);
  const data = bytes.slice(28);
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  const key = await window.crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  try {
    const plainBuf = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      data
    );
    return new TextDecoder().decode(plainBuf);
  } catch {
    throw new Error('WRONG_PASSWORD');
  }
}

// ─── Core process function ────────────────────────────────────
const MAX_INPUT = 500_000; // ~500 KB — prevent main-thread hang

function process() {
  const text = inputText.value;
  if (text.length > MAX_INPUT) {
    outputText.value = '⚠ Input too large (max 500 KB)';
    return;
  }
  let result = '';
  let isError = false;
  let isWarning = false;

  const shift    = Math.max(1, Math.min(85, parseInt(caesarKey.value) || 1));
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
      if (mode === 'decrypt' && text.length > 0) isWarning = true;
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
      if (mode === 'decrypt' && text.length > 0) isWarning = true;
      break;
  }

  outputText.value = result;

  // Flash output
  outputPanel.classList.remove('output-flash', 'error', 'warning');
  void outputPanel.offsetWidth; // reflow
  if (isError)        outputPanel.classList.add('error');
  else if (isWarning) outputPanel.classList.add('warning');
  else                outputPanel.classList.add('output-flash');

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
  syncMobileNav();
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
      keyLabel.textContent = 'Shift (1–85)';
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
  if (meta) meta.setAttribute('content', isDark ? '#0d0d0d' : '#f9f8f6');
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

navEncrypt.addEventListener('click', () => setMode('encrypt'));
navDecrypt.addEventListener('click', () => setMode('decrypt'));
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
    navigator.serviceWorker.register('./sw.js').catch(err => console.warn('SW registration failed:', err));
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
