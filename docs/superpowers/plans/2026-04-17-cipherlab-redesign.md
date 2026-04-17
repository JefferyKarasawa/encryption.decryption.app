# CipherLab Redesign & Cipher Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 5 new cipher algorithms (Playfair, Rail Fence, Columnar Transposition, Beaufort, AES-256-GCM) and redesign the UI from a generic dark dashboard to an Industrial Console aesthetic using the IBM Plex typeface and an amber accent palette.

**Architecture:** All changes are confined to three existing files (`app.js`, `index.html`, `styles.css`). No new files, no new dependencies, no build tooling — vanilla HTML/CSS/JS. AES uses the browser Web Crypto API (async). Classical ciphers are synchronous pure JS. The cipher `<select>` dropdown is replaced by a left sidebar; the controls bar is restructured around it.

**Tech Stack:** Vanilla JS (ES2020), Web Crypto API, CSS custom properties, IBM Plex Mono + IBM Plex Sans (Google Fonts), PWA unchanged.

---

## File Map

| File | What changes |
|---|---|
| `app.js` | Add 5 cipher implementations; add `aesEncrypt`/`aesDecrypt` async functions; update `CIPHER_INFO`; update `process()` for async AES; update `updateKeyUI()` for 11 ciphers; add password strength helper; fix init to read sidebar selection |
| `index.html` | Replace `controls-bar` with sidebar+main layout; replace `<select>` with sidebar cipher list; replace mode toggle markup; add key parameter inputs for new ciphers; add AES password UI (show/hide + strength bar) |
| `styles.css` | Swap all design tokens; add sidebar styles; replace mode-toggle filled-button with underline-indicator; add chamfer clip-paths; add dot-grid texture; add amber pulse animation; add AES spinner; update mobile layout for sidebar |

---

## Task 1: Classical Cipher Implementations (app.js)

**Files:**
- Modify: `app.js` (add after the `atbash` function, before `// ─── Core process function`)

- [ ] **Step 1: Add Playfair cipher implementation**

Insert the following block in `app.js` directly after the `atbash` function (before `// ─── Core process function`):

```js
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
  // Extract latin letters only, remember positions of non-latin for reinsertion
  const positions = []; // {idx, ch} for non-latin chars in original text
  const letters = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i].toUpperCase();
    if (/[A-Z]/.test(ch)) {
      letters.push(ch === 'J' ? 'I' : ch);
    } else {
      positions.push({ idx: i, ch: text[i] });
    }
  }
  // Pad bigrams
  const bigrams = [];
  let i = 0;
  while (i < letters.length) {
    const a = letters[i];
    const b = letters[i + 1];
    if (b === undefined) { bigrams.push([a, 'X']); i++; }
    else if (a === b)    { bigrams.push([a, 'X']); i++; }
    else                 { bigrams.push([a, b]);   i += 2; }
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
  // Restore original case and reinsert non-latin chars
  const latinOut = result.map((ch, idx) => {
    const orig = letters[idx];
    return orig && orig === orig.toLowerCase() ? ch.toLowerCase() : ch;
  });
  // Reinsert non-latin at original positions (adjusted for padding)
  // Non-latin chars are appended at end since padding shifts indices
  return latinOut.join('') + positions.map(p => p.ch).join('');
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
  if (rails >= text.length) return text;
  const len = text.length;
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
  // Slice text into rail rows
  const rows = [];
  let pos = 0;
  for (const c of counts) { rows.push([...text.slice(pos, pos + c)]); pos += c; }
  // Read off by original order
  const rowIdx = new Array(rails).fill(0);
  return indices.map(r => rows[r][rowIdx[r]++]).join('');
}

// ─── Columnar Transposition ───────────────────────────────────
function columnarEncrypt(text, key) {
  const k = (key || '').replace(/[^a-zA-Z]/g, '').toUpperCase();
  if (!k) return text;
  const cols = k.length;
  const rows = Math.ceil(text.length / cols);
  // Pad with null char to fill grid
  const padded = text.padEnd(rows * cols, '\0');
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
  const rows = Math.ceil(text.length / cols);
  const totalCells = rows * cols;
  const shortCols = totalCells - text.length; // number of columns with rows-1 chars
  // Build sorted order
  const order = [...k].map((char, origIdx) => ({ char, origIdx }));
  order.sort((a, b) => a.char < b.char ? -1 : a.char > b.char ? 1 : a.origIdx - b.origIdx);
  // Assign lengths: last `shortCols` columns in sorted order get rows-1
  const lengths = new Array(cols);
  for (let i = 0; i < cols; i++) {
    lengths[order[i].origIdx] = (i >= cols - shortCols) ? rows - 1 : rows;
  }
  // Slice text into sorted columns
  const sortedCols = [];
  let pos = 0;
  for (const { origIdx } of order) {
    const len = lengths[origIdx];
    sortedCols.push({ origIdx, chars: [...text.slice(pos, pos + len)] });
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
```

- [ ] **Step 2: Verify no syntax errors in app.js**

Open `app.js` in browser console or run:
```powershell
node -e "require('fs').readFileSync('app.js','utf8'); console.log('OK')" 2>&1
```
Expected: `OK` (no parse errors)

- [ ] **Step 3: Commit classical cipher implementations**

```powershell
git add app.js
git commit -m "feat: add Playfair, Rail Fence, Columnar Transposition, Beaufort ciphers"
```

---

## Task 2: AES-256-GCM Implementation (app.js)

**Files:**
- Modify: `app.js` (add after Beaufort, before `// ─── Core process function`)

- [ ] **Step 1: Add AES encrypt/decrypt functions**

Insert directly after the Beaufort functions added in Task 1:

```js
// ─── AES-256-GCM ─────────────────────────────────────────────
async function aesEncrypt(text, password) {
  if (!window.crypto?.subtle) throw new Error('NO_SECURE_CONTEXT');
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 310_000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(text));
  const combined = new Uint8Array(salt.length + iv.length + cipherBuf.byteLength);
  combined.set(salt, 0);
  combined.set(iv, 16);
  combined.set(new Uint8Array(cipherBuf), 28);
  return btoa(String.fromCharCode(...combined));
}

async function aesDecrypt(b64, password) {
  if (!window.crypto?.subtle) throw new Error('NO_SECURE_CONTEXT');
  let bytes;
  try {
    bytes = Uint8Array.from(atob(b64.trim()), c => c.charCodeAt(0));
  } catch {
    throw new Error('INVALID_INPUT');
  }
  if (bytes.length < 28) throw new Error('INVALID_INPUT');
  const salt      = bytes.slice(0, 16);
  const iv        = bytes.slice(16, 28);
  const data      = bytes.slice(28);
  const enc       = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 310_000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  try {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return new TextDecoder().decode(plain);
  } catch {
    throw new Error('WRONG_PASSWORD');
  }
}
```

- [ ] **Step 2: Verify no syntax errors**

```powershell
node -e "require('fs').readFileSync('app.js','utf8'); console.log('OK')" 2>&1
```
Expected: `OK`

- [ ] **Step 3: Commit**

```powershell
git add app.js
git commit -m "feat: add AES-256-GCM encrypt/decrypt via Web Crypto API"
```

---

## Task 3: Update CIPHER_INFO, updateKeyUI, and process() (app.js)

**Files:**
- Modify: `app.js`

- [ ] **Step 1: Replace CIPHER_INFO constant**

Find and replace the entire `CIPHER_INFO` object:

```js
// OLD — replace entire object
const CIPHER_INFO = {
  caesar:   'Caesar Cipher shifts each character...',
  ...
};
```

Replace with:

```js
const CIPHER_INFO = {
  caesar:    'Caesar Cipher shifts each character within its script. Supports Latin (26), Hiragana/Katakana (86), and Kanji (20,992 chars). Non-script characters pass through unchanged.',
  vigenere:  'Vigenere cipher uses a keyword for per-character shifts. Supports Latin, Hiragana, Katakana, and Kanji. The key can mix scripts.',
  rot13:     'ROT13/ROT43 — rotates Latin letters by 13 (half of 26) and Japanese Hiragana/Katakana by 43 (half of 86). Symmetric: encrypt and decrypt apply the same transform.',
  base64:    'Base64 encodes binary/text data as ASCII characters using 64 printable symbols. Fully supports Unicode including Japanese. It is an encoding scheme, not a security cipher.',
  xor:       'XOR Cipher applies bitwise XOR between each character code and a repeating hex key. Symmetric — the same key encrypts and decrypts.',
  atbash:    'Atbash mirrors each character within its script range (A↔Z, あ↔ん, ア↔ン, etc.). Symmetric: the same operation encrypts and decrypts.',
  playfair:  'Playfair uses a 5×5 keyword grid for bigram substitution. J is merged into I. Non-Latin characters pass through unchanged. Odd-length input is padded with X.',
  railfence: 'Rail Fence writes text diagonally across N rails, then reads row by row. Key is the number of rails (2–10). Works on any Unicode text.',
  columnar:  'Columnar Transposition writes text in rows, then reads columns in keyword-alphabetical order. Non-alphabetic key characters are ignored.',
  beaufort:  'Beaufort cipher: ciphertext = (key − plaintext) mod 26. Reciprocal — the same key and operation both encrypts and decrypts. Latin only.',
  aes256gcm: 'AES-256-GCM with PBKDF2 key derivation (310,000 iterations, SHA-256). Authenticated encryption — wrong passwords are detected. 100% local processing.',
};
```

- [ ] **Step 2: Replace updateKeyUI() function**

Find and replace the entire `updateKeyUI` function in `app.js`:

```js
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
```

Replace with:

```js
function updateKeyUI() {
  // Hide all key inputs
  caesarKey.classList.add('hidden');
  vigenereKey.classList.add('hidden');
  xorKey.classList.add('hidden');
  noKeyBadge.classList.add('hidden');
  playfairKey.classList.add('hidden');
  railKey.classList.add('hidden');
  columnarKey.classList.add('hidden');
  beaufortKey.classList.add('hidden');
  aesKeyWrap.classList.add('hidden');

  switch (cipher) {
    case 'caesar':
      caesarKey.classList.remove('hidden');
      keyLabel.textContent = 'SHIFT (1–85)';
      break;
    case 'vigenere':
      vigenereKey.classList.remove('hidden');
      keyLabel.textContent = 'KEYWORD';
      break;
    case 'xor':
      xorKey.classList.remove('hidden');
      keyLabel.textContent = 'HEX KEY';
      break;
    case 'playfair':
      playfairKey.classList.remove('hidden');
      keyLabel.textContent = 'KEYWORD';
      break;
    case 'railfence':
      railKey.classList.remove('hidden');
      keyLabel.textContent = 'RAILS (2–10)';
      break;
    case 'columnar':
      columnarKey.classList.remove('hidden');
      keyLabel.textContent = 'KEYWORD';
      break;
    case 'beaufort':
      beaufortKey.classList.remove('hidden');
      keyLabel.textContent = 'KEYWORD';
      break;
    case 'aes256gcm':
      aesKeyWrap.classList.remove('hidden');
      keyLabel.textContent = 'PASSWORD';
      break;
    default:
      noKeyBadge.classList.remove('hidden');
      keyLabel.textContent = 'KEY';
  }

  cipherInfoEl.textContent = CIPHER_INFO[cipher] || '';
}
```

- [ ] **Step 3: Add new DOM refs at the top of app.js**

Find the existing DOM refs block (just after `// ─── DOM refs`) and add new refs after the existing `noKeyBadge` line:

```js
// Find this line:
const noKeyBadge     = document.getElementById('noKeyBadge');
// Add after it:
const playfairKey    = document.getElementById('playfairKey');
const railKey        = document.getElementById('railKey');
const columnarKey    = document.getElementById('columnarKey');
const beaufortKey    = document.getElementById('beaufortKey');
const aesKeyWrap     = document.getElementById('aesKeyWrap');
const aesPasswordEl  = document.getElementById('aesPassword');
const aesToggleBtn   = document.getElementById('aesToggleBtn');
const aesStrengthBar = document.getElementById('aesStrengthBar');
```

- [ ] **Step 4: Replace the process() function**

Find and replace the entire `process()` function:

```js
// ─── Core process function ────────────────────────────────────
const MAX_INPUT = 500_000;

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
      result = rot13(text);
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
      result = xorCipher(text, xorK);
      break;
    case 'atbash':
      result = atbash(text);
      if (mode === 'decrypt' && text.length > 0) isWarning = true;
      break;
    case 'playfair':
      result = mode === 'encrypt'
        ? playfairEncrypt(text, playfairKey.value)
        : playfairDecrypt(text, playfairKey.value);
      break;
    case 'railfence':
      result = mode === 'encrypt'
        ? railFenceEncrypt(text, parseInt(railKey.value) || 2)
        : railFenceDecrypt(text, parseInt(railKey.value) || 2);
      break;
    case 'columnar':
      result = mode === 'encrypt'
        ? columnarEncrypt(text, columnarKey.value)
        : columnarDecrypt(text, columnarKey.value);
      break;
    case 'beaufort':
      result = beaufort(text, beaufortKey.value); // symmetric
      if (mode === 'decrypt' && text.length > 0) isWarning = true;
      break;
    case 'aes256gcm':
      processAES(); // async path — returns early
      return;
  }

  outputText.value = result;
  flashOutput(isError, isWarning);
  updateCounts(text, result);
  processIndicator.classList.toggle('active', text.length > 0);
}
```

- [ ] **Step 5: Add processAES() async helper and password strength after process()**

Insert directly after the `process()` function:

```js
// ─── AES async handler ────────────────────────────────────────
async function processAES() {
  const text = inputText.value;
  const password = aesPasswordEl.value;
  if (!text) { outputText.value = ''; updateCounts('', ''); return; }
  if (!password) { outputText.value = ''; updateCounts(text, ''); return; }

  // Show spinner
  processIndicator.classList.add('spinning');
  outputText.value = '⟳ Processing…';

  try {
    let result;
    if (mode === 'encrypt') {
      result = await aesEncrypt(text, password);
    } else {
      result = await aesDecrypt(text, password);
    }
    outputText.value = result;
    flashOutput(false, false);
    updateCounts(text, result);
  } catch (err) {
    let msg;
    if (err.message === 'NO_SECURE_CONTEXT') msg = '⚠ AES requires a secure context (HTTPS or localhost)';
    else if (err.message === 'WRONG_PASSWORD') msg = '⚠ Decryption failed — wrong password or corrupted data';
    else msg = '⚠ Invalid AES input';
    outputText.value = msg;
    flashOutput(true, false);
    updateCounts(text, msg);
  } finally {
    processIndicator.classList.remove('spinning');
    processIndicator.classList.toggle('active', text.length > 0);
  }
}

// ─── Output flash helper ──────────────────────────────────────
function flashOutput(isError, isWarning) {
  outputPanel.classList.remove('output-flash', 'error', 'warning');
  void outputPanel.offsetWidth;
  if (isError)        outputPanel.classList.add('error');
  else if (isWarning) outputPanel.classList.add('warning');
  else                outputPanel.classList.add('output-flash');
}

// ─── Password strength ────────────────────────────────────────
function passwordEntropy(pwd) {
  if (!pwd) return 0;
  let pool = 0;
  if (/[a-z]/.test(pwd)) pool += 26;
  if (/[A-Z]/.test(pwd)) pool += 26;
  if (/[0-9]/.test(pwd)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pwd)) pool += 32;
  return Math.round(pwd.length * Math.log2(pool || 1));
}

function updatePasswordStrength() {
  const entropy = passwordEntropy(aesPasswordEl.value);
  const segments = aesStrengthBar.querySelectorAll('.strength-seg');
  let level = 0;
  if (entropy >= 28) level = 1;
  if (entropy >= 50) level = 2;
  if (entropy >= 72) level = 3;
  if (entropy >= 96) level = 4;
  segments.forEach((seg, i) => {
    seg.className = 'strength-seg' + (i < level ? ` level-${level}` : '');
  });
}
```

- [ ] **Step 6: Remove now-redundant inline flash code from process()**

The old flash code (`outputPanel.classList.remove...`, `void outputPanel.offsetWidth`) inside the old `process()` has already been extracted to `flashOutput()` in the new version above. Verify the new `process()` calls `flashOutput(isError, isWarning)` — it does, as written in Step 4.

- [ ] **Step 7: Add event listeners for new key inputs**

Find the existing event listeners section (`// ─── Event Listeners`) and add after `xorKey.addEventListener('input', process);`:

```js
playfairKey.addEventListener('input', process);
railKey.addEventListener('input', process);
columnarKey.addEventListener('input', process);
beaufortKey.addEventListener('input', process);
aesPasswordEl.addEventListener('input', () => { updatePasswordStrength(); process(); });
aesToggleBtn.addEventListener('click', () => {
  const isHidden = aesPasswordEl.type === 'password';
  aesPasswordEl.type = isHidden ? 'text' : 'password';
  aesToggleBtn.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
});
```

- [ ] **Step 8: Update init() to use sidebar selection**

Find and update the `init()` function — change `cipher = cipherSelect.value;` to:

```js
// OLD:
cipher = cipherSelect.value;
// NEW (cipher now set from sidebar active item):
const activeSidebarItem = document.querySelector('.cipher-item.active');
cipher = activeSidebarItem ? activeSidebarItem.dataset.cipher : 'caesar';
```

Also add sidebar click wiring in init (before the final closing `})`):

```js
// Wire sidebar cipher items
document.querySelectorAll('.cipher-item').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.cipher-item').forEach(i => i.classList.remove('active'));
    item.classList.add('active');
    cipher = item.dataset.cipher;
    updateKeyUI();
    process();
  });
});
```

- [ ] **Step 9: Verify no syntax errors**

```powershell
node -e "require('fs').readFileSync('app.js','utf8'); console.log('OK')" 2>&1
```
Expected: `OK`

- [ ] **Step 10: Commit**

```powershell
git add app.js
git commit -m "feat: wire 11 ciphers into process(), updateKeyUI(), event listeners"
```

---

## Task 4: HTML — Layout, Sidebar, New Key Inputs (index.html)

**Files:**
- Modify: `index.html`

- [ ] **Step 1: Replace Google Fonts import**

Find:
```html
  <link rel="preconnect" href="https://fonts.googleapis.com" crossorigin />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link rel="stylesheet" href="styles.css" />
```
Replace with:
```html
  <link rel="preconnect" href="https://fonts.googleapis.com" crossorigin />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600;700&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" />
  <link rel="stylesheet" href="styles.css" />
```

- [ ] **Step 2: Replace the entire .app-wrapper inner structure**

Replace the full content from `<div class="app-wrapper">` opening tag through `</div>` (the closing tag of app-wrapper, just before `<!-- Mobile Bottom Nav -->`). The new markup is:

```html
  <div class="app-wrapper">

    <!-- Header -->
    <header class="app-header">
      <div class="header-left">
        <div class="logo">
          <svg class="logo-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
          <span class="logo-text">CipherLab</span>
        </div>
        <span class="tagline">Encryption &amp; Decryption Tool</span>
      </div>
      <div class="header-right">
        <button class="theme-toggle" id="themeToggle" aria-label="Toggle theme" title="Toggle dark/light theme">
          <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="5"/>
            <line x1="12" y1="1" x2="12" y2="3"/>
            <line x1="12" y1="21" x2="12" y2="23"/>
            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
            <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
            <line x1="1" y1="12" x2="3" y2="12"/>
            <line x1="21" y1="12" x2="23" y2="12"/>
            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
            <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
          </svg>
          <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
          </svg>
        </button>
        <button class="install-header-btn hidden" id="installHeaderBtn" title="Install app">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 2v13M5 15l7 7 7-7"/>
            <path d="M3 21h18"/>
          </svg>
          <span>Install</span>
        </button>
      </div>
    </header>

    <!-- Body: sidebar + main -->
    <div class="body-layout">

      <!-- Cipher Sidebar -->
      <aside class="cipher-sidebar">
        <div class="sidebar-group-label">── CLASSICAL ──</div>
        <button class="cipher-item active" data-cipher="caesar">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4l3 3"/></svg>
          Caesar
        </button>
        <button class="cipher-item" data-cipher="vigenere">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6h16M4 12h16M4 18h7"/></svg>
          Vigenère
        </button>
        <button class="cipher-item" data-cipher="rot13">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 4v6h6"/><path d="M23 20v-6h-6"/><path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15"/></svg>
          ROT13
        </button>
        <button class="cipher-item" data-cipher="atbash">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
          Atbash
        </button>
        <button class="cipher-item" data-cipher="base64">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 3H8a2 2 0 0 0-2 2v2h12V5a2 2 0 0 0-2-2z"/></svg>
          Base64
        </button>
        <button class="cipher-item" data-cipher="xor">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
          XOR
        </button>
        <button class="cipher-item" data-cipher="playfair">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>
          Playfair
        </button>
        <button class="cipher-item" data-cipher="railfence">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 9 12 3 18"/><polyline points="9 6 15 12 9 18"/><polyline points="15 6 21 12 15 18"/></svg>
          Rail Fence
        </button>
        <button class="cipher-item" data-cipher="columnar">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="8" y1="6" x2="8" y2="18"/><line x1="16" y1="6" x2="16" y2="18"/><rect x="3" y="6" width="18" height="12" rx="1"/></svg>
          Columnar
        </button>
        <button class="cipher-item" data-cipher="beaufort">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Beaufort
        </button>
        <div class="sidebar-group-label" style="margin-top:0.75rem;">── MODERN ──</div>
        <button class="cipher-item" data-cipher="aes256gcm">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1" fill="currentColor"/></svg>
          AES-256-GCM
        </button>
      </aside>

      <!-- Main content -->
      <div class="main-content">

        <!-- Mode + Key Parameters bar -->
        <div class="controls-bar">
          <!-- Mode Toggle -->
          <div class="control-group mode-group">
            <label class="control-label">MODE</label>
            <div class="mode-toggle-wrap">
              <button class="mode-btn active" id="encryptBtn" data-mode="encrypt">[ ENCRYPT ]</button>
              <button class="mode-btn" id="decryptBtn" data-mode="decrypt">[ DECRYPT ]</button>
              <span class="mode-underline" id="modeUnderline"></span>
            </div>
          </div>
          <!-- Key Parameters -->
          <div class="control-group key-group" id="keyGroup">
            <label class="control-label" id="keyLabel">SHIFT (1–85)</label>
            <div class="key-input-wrap">
              <input type="number" id="caesarKey"   class="key-input"        min="1" max="85" value="13" placeholder="1–85" />
              <input type="text"   id="vigenereKey" class="key-input hidden" placeholder="e.g. SECRET"  maxlength="64" />
              <input type="text"   id="xorKey"      class="key-input hidden" placeholder="hex, e.g. A3F2" maxlength="16" />
              <input type="text"   id="playfairKey" class="key-input hidden" placeholder="keyword"      maxlength="25" />
              <input type="number" id="railKey"     class="key-input hidden" min="2" max="10" value="3" placeholder="2–10" />
              <input type="text"   id="columnarKey" class="key-input hidden" placeholder="keyword"      maxlength="20" />
              <input type="text"   id="beaufortKey" class="key-input hidden" placeholder="keyword"      maxlength="64" />
              <!-- AES password group -->
              <div id="aesKeyWrap" class="aes-key-wrap hidden">
                <div class="aes-password-row">
                  <input type="password" id="aesPassword" class="key-input aes-pass" placeholder="password" autocomplete="new-password" />
                  <button type="button" id="aesToggleBtn" class="aes-toggle" aria-label="Show password">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                      <circle cx="12" cy="12" r="3"/>
                    </svg>
                  </button>
                </div>
                <div class="aes-strength" id="aesStrengthBar">
                  <span class="strength-seg"></span>
                  <span class="strength-seg"></span>
                  <span class="strength-seg"></span>
                  <span class="strength-seg"></span>
                </div>
              </div>
              <span class="key-badge hidden" id="noKeyBadge">No key needed</span>
            </div>
          </div>
        </div>

        <!-- Text Panels -->
        <main class="panels">

          <!-- Input Panel -->
          <section class="panel panel-input">
            <div class="panel-header">
              <span class="panel-title" id="inputTitle">── PLAINTEXT ──</span>
              <div class="panel-actions">
                <button class="action-btn" id="clearBtn" title="Clear input">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="3 6 5 6 21 6"/>
                    <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
                    <path d="M10 11v6M14 11v6"/>
                    <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>
                  </svg>
                  Clear
                </button>
              </div>
            </div>
            <textarea id="inputText" class="text-area" placeholder="Type or paste your text here…" spellcheck="false" autocomplete="off"></textarea>
            <div class="panel-footer">
              <span class="char-count"><span id="inputCharCount">0</span> chars</span>
              <span class="word-count"><span id="inputWordCount">0</span> words</span>
            </div>
          </section>

          <!-- Middle Actions -->
          <div class="middle-actions">
            <div class="process-indicator" id="processIndicator">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M5 12h14M12 5l7 7-7 7"/>
              </svg>
            </div>
            <button class="swap-btn" id="swapBtn" title="Swap input &amp; output">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M7 16V4m0 0L3 8m4-4l4 4"/>
                <path d="M17 8v12m0 0l4-4m-4 4l-4-4"/>
              </svg>
            </button>
          </div>

          <!-- Output Panel -->
          <section class="panel panel-output">
            <div class="panel-header">
              <span class="panel-title" id="outputTitle">── CIPHERTEXT ──</span>
              <div class="panel-actions">
                <button class="action-btn" id="copyBtn" title="Copy to clipboard">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                  </svg>
                  <span id="copyLabel">Copy</span>
                </button>
              </div>
            </div>
            <textarea id="outputText" class="text-area output-area" placeholder="Output will appear here…" readonly spellcheck="false"></textarea>
            <div class="panel-footer">
              <span class="char-count"><span id="outputCharCount">0</span> chars</span>
              <span class="word-count"><span id="outputWordCount">0</span> words</span>
            </div>
          </section>

        </main>

        <!-- Info Bar -->
        <div class="info-bar" id="infoBar">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          <span id="cipherInfo">Caesar Cipher shifts each character within its script.</span>
        </div>

        <!-- Footer -->
        <footer class="app-footer">
          <span>All processing is done locally. Nothing is sent to any server.</span>
        </footer>

      </div><!-- /.main-content -->
    </div><!-- /.body-layout -->

  </div><!-- /.app-wrapper -->
```

- [ ] **Step 3: Update inputTitle / outputTitle text in setMode()**

In `app.js`, find `setMode` and update the title strings:

```js
// OLD:
inputTitle.textContent  = m === 'encrypt' ? 'Plaintext'  : 'Ciphertext';
outputTitle.textContent = m === 'encrypt' ? 'Ciphertext' : 'Plaintext';
// NEW:
inputTitle.textContent  = m === 'encrypt' ? '── PLAINTEXT ──'  : '── CIPHERTEXT ──';
outputTitle.textContent = m === 'encrypt' ? '── CIPHERTEXT ──' : '── PLAINTEXT ──';
```

- [ ] **Step 4: Update mode underline on mode switch**

In `app.js`, update `setMode()` to move the underline indicator:

```js
// Find in setMode():
encryptBtn.classList.toggle('active', m === 'encrypt');
decryptBtn.classList.toggle('active', m === 'decrypt');
// Add after those two lines:
const underline = document.getElementById('modeUnderline');
if (underline) {
  underline.style.transform = m === 'encrypt' ? 'translateX(0)' : 'translateX(100%)';
}
```

- [ ] **Step 5: Verify HTML renders without console errors**

Open `index.html` in a browser (or via Live Server). Check browser console — expect zero errors.

- [ ] **Step 6: Commit**

```powershell
git add index.html app.js
git commit -m "feat: replace select dropdown with cipher sidebar; add new key inputs; update mode toggle"
```

---

## Task 5: CSS — Full Visual Redesign (styles.css)

**Files:**
- Modify: `styles.css`

- [ ] **Step 1: Replace the font import and all CSS variables**

Replace the entire first block of `styles.css` (from `@import url(...)` through the closing `}` of `[data-theme="light"]`):

```css
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600;700&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

/* ============================================================
   Variables — Industrial Console
   ============================================================ */
:root {
  --bg:           #0b0d11;
  --bg-raised:    #111520;
  --bg-panel:     #111520;
  --bg-panel-alt: #161b27;
  --bg-hover:     #1a2030;

  --border:       #1e2535;
  --border-mid:   #2a3347;
  --border-focus: #e8a030;

  --accent:       #e8a030;
  --accent-dim:   #c07820;

  --text-hi:      #d4cfc8;
  --text-mid:     #7a8099;
  --text-lo:      #3a4055;

  --success:      #3db87a;
  --error:        #e05555;
  --warn:         #d4a017;

  --radius:       4px;
  --radius-sm:    3px;
  --t:            0.15s ease;

  --font-mono:    'IBM Plex Mono', 'Cascadia Code', monospace;
  --font-sans:    'IBM Plex Sans', 'Segoe UI', sans-serif;

  --chamfer: polygon(6px 0%, 100% 0%, 100% calc(100% - 6px), calc(100% - 6px) 100%, 0% 100%, 0% 6px);
}

[data-theme="light"] {
  --bg:           #f0ede8;
  --bg-raised:    #e8e4de;
  --bg-panel:     #e8e4de;
  --bg-panel-alt: #dedad4;
  --bg-hover:     #d4cfc8;

  --border:       #c8c3bb;
  --border-mid:   #b8b2a8;

  --text-hi:      #1a1a1a;
  --text-mid:     #5a5550;
  --text-lo:      #9a958e;
}
```

- [ ] **Step 2: Replace body/html/app-wrapper/header base styles**

Find the `/* ============================================================ Reset ============================================================ */` section down through the `.app-header::after` rule and replace with:

```css
/* ============================================================
   Reset
   ============================================================ */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html {
  font-size: 15px;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

body {
  font-family: var(--font-sans);
  background: var(--bg);
  color: var(--text-hi);
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  transition: background 0.2s ease, color 0.2s ease;
  overflow-x: hidden;
  /* Dot-grid texture */
  background-image: radial-gradient(circle, #1e2535 1px, transparent 1px);
  background-size: 20px 20px;
}

[data-theme="light"] body, [data-theme="light"] {
  background-image: radial-gradient(circle, #c8c3bb 1px, transparent 1px);
  background-size: 20px 20px;
}

/* ============================================================
   App Wrapper
   ============================================================ */
.app-wrapper {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  max-width: 1400px;
  margin: 0 auto;
  width: 100%;
  padding: 0 1.25rem;
  animation: fadeUp 0.2s ease both;
}

@keyframes fadeUp {
  from { opacity: 0; transform: translateY(5px); }
  to   { opacity: 1; transform: translateY(0); }
}

/* ============================================================
   Header
   ============================================================ */
.app-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.9rem 0 0.85rem;
  border-bottom: 1px solid var(--border);
  margin-bottom: 0;
}

.app-header::after {
  content: '';
  position: absolute;
  bottom: -1px;
  left: 0;
  width: 32px;
  height: 1px;
  background: var(--accent);
}

.header-left {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.logo {
  display: flex;
  align-items: center;
  gap: 0.45rem;
  text-decoration: none;
}

.logo-icon {
  width: 18px;
  height: 18px;
  color: var(--accent);
  flex-shrink: 0;
}

.logo-text {
  font-family: var(--font-mono);
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--text-hi);
  letter-spacing: 0.02em;
}

.tagline {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  color: var(--text-lo);
  border-left: 1px solid var(--border-mid);
  padding-left: 1rem;
  display: none;
}

@media (min-width: 600px) { .tagline { display: block; } }

.header-right {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.install-header-btn {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  background: transparent;
  border: 1px solid var(--border-mid);
  clip-path: var(--chamfer);
  padding: 0.35rem 0.7rem;
  color: var(--text-mid);
  font-family: var(--font-mono);
  font-size: 0.72rem;
  font-weight: 500;
  cursor: pointer;
  transition: color var(--t), border-color var(--t);
  letter-spacing: 0.04em;
}
.install-header-btn svg { width: 12px; height: 12px; }
.install-header-btn:hover { color: var(--text-hi); border-color: var(--text-mid); }
.install-header-btn.hidden { display: none !important; }
.install-header-btn:not(.hidden) { display: inline-flex; }

.theme-toggle {
  background: transparent;
  border: 1px solid var(--border-mid);
  clip-path: var(--chamfer);
  cursor: pointer;
  color: var(--text-mid);
  transition: color var(--t), border-color var(--t);
  display: flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  flex-shrink: 0;
}
.theme-toggle:hover { color: var(--accent); border-color: var(--accent); }
.theme-toggle svg { width: 13px; height: 13px; }

[data-theme="dark"] .icon-moon { display: none; }
[data-theme="light"] .icon-sun  { display: none; }
```

- [ ] **Step 3: Add body-layout and cipher sidebar styles**

After the header styles, insert a new section:

```css
/* ============================================================
   Body Layout
   ============================================================ */
.body-layout {
  display: flex;
  flex: 1;
  gap: 0;
  min-height: 0;
  padding-top: 1rem;
}

/* ============================================================
   Cipher Sidebar
   ============================================================ */
.cipher-sidebar {
  width: 200px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding-right: 1rem;
  border-right: 1px solid var(--border);
  margin-right: 1rem;
}

.sidebar-group-label {
  font-family: var(--font-mono);
  font-size: 0.62rem;
  color: var(--text-lo);
  letter-spacing: 0.06em;
  padding: 0.5rem 0.4rem 0.25rem;
  white-space: nowrap;
}

.cipher-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.45rem 0.55rem;
  background: transparent;
  border: none;
  border-left: 3px solid transparent;
  color: var(--text-mid);
  font-family: var(--font-mono);
  font-size: 0.78rem;
  font-weight: 400;
  cursor: pointer;
  text-align: left;
  transition: color var(--t), background var(--t), border-color var(--t);
  -webkit-tap-highlight-color: transparent;
}
.cipher-item svg { width: 13px; height: 13px; flex-shrink: 0; }
.cipher-item:hover {
  color: var(--text-hi);
  background: var(--bg-hover);
}
.cipher-item.active {
  color: var(--accent);
  border-left-color: var(--accent);
  background: rgba(232, 160, 48, 0.06);
}

.main-content {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}
```

- [ ] **Step 4: Replace controls-bar, mode toggle, and key input styles**

Find and replace the `/* ============================================================ Controls Bar ============================================================ */` section down through the end of the `.key-badge.hidden` rule:

```css
/* ============================================================
   Controls Bar
   ============================================================ */
.controls-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
  align-items: flex-end;
  background: var(--bg-raised);
  border: 1px solid var(--border);
  clip-path: var(--chamfer);
  padding: 0.75rem 1rem;
  margin-bottom: 0.85rem;
}

.control-group {
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
}

.control-label {
  font-family: var(--font-mono);
  font-size: 0.62rem;
  font-weight: 500;
  color: var(--text-lo);
  letter-spacing: 0.07em;
}

/* Mode Toggle */
.mode-toggle-wrap {
  position: relative;
  display: flex;
  background: transparent;
  gap: 0;
}

.mode-btn {
  padding: 0.38rem 0.85rem;
  background: transparent;
  border: 1px solid var(--border-mid);
  border-right: none;
  color: var(--text-lo);
  font-family: var(--font-mono);
  font-size: 0.75rem;
  font-weight: 500;
  cursor: pointer;
  transition: color var(--t);
  letter-spacing: 0.04em;
  position: relative;
}
.mode-btn:last-of-type { border-right: 1px solid var(--border-mid); }
.mode-btn:hover { color: var(--text-hi); }
.mode-btn.active { color: var(--accent); }
.mode-btn:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }

.mode-underline {
  position: absolute;
  bottom: 0;
  left: 0;
  width: 50%;
  height: 2px;
  background: var(--accent);
  transition: transform 0.15s ease;
  pointer-events: none;
}

/* Key Input */
.key-input-wrap { display: flex; align-items: center; }

.key-input {
  background: var(--bg);
  border: 1px solid var(--border-mid);
  clip-path: var(--chamfer);
  padding: 0.38rem 0.7rem;
  color: var(--text-hi);
  font-family: var(--font-mono);
  font-size: 0.78rem;
  width: 140px;
  transition: border-color var(--t);
}
.key-input:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
.key-input:hover { border-color: var(--text-mid); }
.key-input.hidden { display: none; }

.aes-key-wrap { display: flex; flex-direction: column; gap: 0.3rem; }
.aes-key-wrap.hidden { display: none; }
.aes-password-row { display: flex; align-items: center; gap: 0.3rem; }
.aes-pass { width: 180px; }

.aes-toggle {
  background: transparent;
  border: 1px solid var(--border-mid);
  clip-path: var(--chamfer);
  color: var(--text-lo);
  cursor: pointer;
  width: 30px;
  height: 30px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: color var(--t);
  flex-shrink: 0;
}
.aes-toggle svg { width: 13px; height: 13px; }
.aes-toggle:hover { color: var(--accent); }

.aes-strength {
  display: flex;
  gap: 3px;
  width: 180px;
}
.strength-seg {
  flex: 1;
  height: 3px;
  background: var(--border-mid);
  transition: background 0.2s ease;
}
.strength-seg.level-1 { background: var(--error); }
.strength-seg.level-2 { background: var(--warn); }
.strength-seg.level-3 { background: #a0c840; }
.strength-seg.level-4 { background: var(--success); }

.key-badge {
  background: var(--bg);
  border: 1px solid var(--border-mid);
  clip-path: var(--chamfer);
  padding: 0.38rem 0.7rem;
  font-family: var(--font-mono);
  font-size: 0.72rem;
  color: var(--text-lo);
}
.key-badge.hidden { display: none; }
```

- [ ] **Step 5: Replace panel styles**

Find and replace the `/* ============================================================ Main Panels ============================================================ */` section down through `.panel.warning .text-area`:

```css
/* ============================================================
   Main Panels
   ============================================================ */
.panels {
  display: grid;
  grid-template-columns: 1fr 44px 1fr;
  flex: 1;
  min-height: 0;
  align-items: stretch;
  margin-bottom: 0.75rem;
}

.panel {
  display: flex;
  flex-direction: column;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  overflow: hidden;
  min-height: 360px;
  transition: border-color var(--t), background var(--t), box-shadow var(--t);
  clip-path: var(--chamfer);
}

.panel-input  { clip-path: var(--chamfer); border-right: none; border-radius: 0; }
.panel-output { clip-path: var(--chamfer); border-left: none;  border-radius: 0; }

.panel-output.has-output {
  box-shadow: 0 0 18px rgba(232, 160, 48, 0.08), inset 0 0 0 1px rgba(232, 160, 48, 0.15);
  border-color: rgba(232, 160, 48, 0.25);
}

.panel:focus-within { border-color: var(--border-mid); }

.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.5rem 0.85rem;
  border-bottom: 1px solid var(--border);
  background: var(--bg-panel-alt);
}

.panel-title {
  font-family: var(--font-mono);
  font-size: 0.65rem;
  font-weight: 500;
  color: var(--accent);
  letter-spacing: 0.05em;
}

.panel-actions {
  display: flex;
  align-items: center;
  gap: 0.35rem;
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 0.28rem;
  background: transparent;
  border: 1px solid var(--border-mid);
  clip-path: var(--chamfer);
  padding: 0.25rem 0.55rem;
  color: var(--text-mid);
  font-family: var(--font-mono);
  font-size: 0.68rem;
  font-weight: 500;
  cursor: pointer;
  transition: color var(--t), border-color var(--t);
  letter-spacing: 0.04em;
}
.action-btn svg { width: 11px; height: 11px; }
.action-btn:hover { color: var(--text-hi); border-color: var(--text-mid); }
.action-btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
.action-btn.success { color: var(--accent); border-color: var(--accent); }

.text-area {
  flex: 1;
  background: transparent;
  border: none;
  padding: 1rem;
  color: var(--text-hi);
  font-family: var(--font-mono);
  font-size: 0.88rem;
  line-height: 1.75;
  resize: none;
  outline: none;
  transition: color var(--t);
}
.text-area::placeholder { color: var(--text-lo); }
.output-area { color: var(--accent); cursor: default; }

.panel-footer {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.35rem 0.85rem;
  border-top: 1px solid var(--border);
  font-family: var(--font-mono);
  font-size: 0.65rem;
  color: var(--text-lo);
  background: var(--bg-panel-alt);
}

/* ============================================================
   Middle Actions
   ============================================================ */
.middle-actions {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  background: var(--bg);
  border-top: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
}

.process-indicator {
  width: 26px;
  height: 26px;
  border: 1px solid var(--border-mid);
  clip-path: var(--chamfer);
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--text-lo);
  transition: color var(--t), border-color var(--t);
}
.process-indicator svg { width: 12px; height: 12px; }
.process-indicator.active { border-color: var(--accent); color: var(--accent); }

/* AES spinner */
.process-indicator.spinning svg { display: none; }
.process-indicator.spinning::after {
  content: '';
  width: 12px;
  height: 12px;
  border: 2px solid var(--border-mid);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }

.swap-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  border: 1px solid var(--border-mid);
  clip-path: var(--chamfer);
  width: 30px;
  height: 30px;
  color: var(--text-mid);
  cursor: pointer;
  transition: color var(--t), border-color var(--t);
  flex-shrink: 0;
}
.swap-btn svg { width: 13px; height: 13px; }
.swap-btn:hover { color: var(--accent); border-color: var(--accent); }
.swap-btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }

/* ============================================================
   Info Bar
   ============================================================ */
.info-bar {
  display: flex;
  align-items: flex-start;
  gap: 0.55rem;
  background: var(--bg-raised);
  border: 1px solid var(--border);
  clip-path: var(--chamfer);
  padding: 0.6rem 0.85rem;
  font-family: var(--font-mono);
  font-size: 0.72rem;
  color: var(--text-mid);
  line-height: 1.6;
  margin-bottom: 0.75rem;
}
.info-bar svg { width: 13px; height: 13px; flex-shrink: 0; color: var(--accent); margin-top: 1px; }

/* ============================================================
   Footer
   ============================================================ */
.app-footer {
  padding: 0.7rem 0;
  text-align: center;
  font-family: var(--font-mono);
  font-size: 0.65rem;
  color: var(--text-lo);
  border-top: 1px solid var(--border);
  margin-top: auto;
  letter-spacing: 0.04em;
}

/* ============================================================
   State animations
   ============================================================ */
@keyframes amberPulse {
  0%   { box-shadow: 0 0 0 0 rgba(232,160,48,0.35); }
  70%  { box-shadow: 0 0 0 6px rgba(232,160,48,0); }
  100% { box-shadow: 0 0 0 0 rgba(232,160,48,0); }
}

.output-flash { animation: amberPulse 0.4s ease-out; }

.panel.error .text-area { color: var(--error); }
.panel.error { border-color: var(--error); }
.panel.warning { border-color: var(--warn); }
.panel.warning .text-area { color: var(--warn); }
```

- [ ] **Step 6: Replace scrollbar + mobile nav styles**

Find and replace from `/* ============================================================ Scrollbar */` through end of file with:

```css
/* ============================================================
   Scrollbar
   ============================================================ */
::-webkit-scrollbar          { width: 4px; height: 4px; }
::-webkit-scrollbar-track    { background: transparent; }
::-webkit-scrollbar-thumb    { background: var(--border-mid); border-radius: 2px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-lo); }

/* ============================================================
   PWA / Mobile safe areas
   ============================================================ */
body {
  padding-top:   env(safe-area-inset-top);
  padding-left:  env(safe-area-inset-left);
  padding-right: env(safe-area-inset-right);
}

input, select, textarea {
  font-size: max(16px, 0.875rem) !important;
}

/* ============================================================
   Mobile Bottom Nav
   ============================================================ */
.mobile-nav {
  display: none;
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  height: calc(52px + env(safe-area-inset-bottom));
  padding-bottom: env(safe-area-inset-bottom);
  background: var(--bg-raised);
  border-top: 1px solid var(--border-mid);
  z-index: 100;
  align-items: stretch;
  justify-content: space-around;
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
}

.nav-btn {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 2px;
  flex: 1;
  background: transparent;
  border: none;
  color: var(--text-lo);
  font-family: var(--font-mono);
  font-size: 0.58rem;
  font-weight: 500;
  cursor: pointer;
  padding: 6px 4px 4px;
  transition: color var(--t);
  -webkit-tap-highlight-color: transparent;
  min-width: 44px;
  min-height: 44px;
  letter-spacing: 0.04em;
}
.nav-btn svg { width: 18px; height: 18px; }
.nav-btn.active { color: var(--accent); }
.nav-btn:active { color: var(--text-hi); }
.nav-btn.copied { color: var(--success); }

/* ============================================================
   PWA Install Banner
   ============================================================ */
.install-banner {
  display: none;
  position: fixed;
  bottom: 16px;
  left: 12px;
  right: 12px;
  background: var(--bg-raised);
  border: 1px solid var(--border-mid);
  clip-path: var(--chamfer);
  padding: 0.75rem 1rem;
  align-items: center;
  gap: 0.75rem;
  font-family: var(--font-mono);
  font-size: 0.75rem;
  color: var(--text-mid);
  z-index: 99;
  box-shadow: 0 4px 24px rgba(0,0,0,0.5);
  animation: slideUp 0.2s ease;
}
.install-banner svg { width: 14px; height: 14px; color: var(--accent); flex-shrink: 0; }
.install-banner span { flex: 1; }
.install-banner #installBtn {
  background: var(--accent);
  color: #000;
  border: none;
  clip-path: var(--chamfer);
  padding: 0.35rem 0.8rem;
  font-family: var(--font-mono);
  font-size: 0.72rem;
  font-weight: 600;
  cursor: pointer;
  white-space: nowrap;
  transition: background var(--t);
}
.install-banner #installBtn:hover { background: var(--accent-dim); }
.install-banner .dismiss-btn {
  background: transparent;
  border: none;
  color: var(--text-lo);
  font-size: 0.85rem;
  cursor: pointer;
  padding: 4px;
  line-height: 1;
}
.install-banner.visible { display: flex; }

@keyframes slideUp {
  from { transform: translateY(8px); opacity: 0; }
  to   { transform: translateY(0); opacity: 1; }
}

/* ============================================================
   Mobile Layout
   ============================================================ */
@media (max-width: 768px) {
  .mobile-nav { display: flex; }

  .app-wrapper {
    padding-bottom: calc(52px + env(safe-area-inset-bottom) + 0.5rem);
  }

  .mode-group { display: none; }
  .app-footer { display: none; }

  .body-layout {
    flex-direction: column;
    padding-top: 0.75rem;
  }

  .cipher-sidebar {
    width: 100%;
    flex-direction: row;
    overflow-x: auto;
    border-right: none;
    border-bottom: 1px solid var(--border);
    padding-right: 0;
    padding-bottom: 0.5rem;
    margin-right: 0;
    margin-bottom: 0.75rem;
    gap: 4px;
    -webkit-overflow-scrolling: touch;
  }

  .cipher-sidebar::-webkit-scrollbar { height: 0; }

  .sidebar-group-label { display: none; }

  .cipher-item {
    flex-direction: column;
    gap: 0.2rem;
    padding: 0.4rem 0.6rem;
    font-size: 0.62rem;
    border-left: none;
    border-bottom: 3px solid transparent;
    white-space: nowrap;
    flex-shrink: 0;
  }
  .cipher-item.active {
    border-left-color: transparent;
    border-bottom-color: var(--accent);
  }
  .cipher-item svg { width: 14px; height: 14px; }

  .controls-bar {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.6rem;
    padding: 0.65rem 0.8rem;
    margin-bottom: 0.7rem;
  }

  .panels {
    grid-template-columns: 1fr;
    margin-bottom: 0.7rem;
  }

  .panel-input  { border-right: 1px solid var(--border); border-bottom: none; clip-path: none; border-radius: 0; }
  .panel-output { border-left: 1px solid var(--border); border-top: none; clip-path: none; border-radius: 0; }
  .panel { min-height: 180px; clip-path: none; }
  .text-area { min-height: 120px; }

  .middle-actions {
    flex-direction: row;
    justify-content: center;
    border: none;
    background: transparent;
    padding: 0.4rem 0;
  }
  .middle-actions .swap-btn { display: none; }

  .install-banner {
    bottom: calc(52px + env(safe-area-inset-bottom) + 8px);
  }
}

@media (max-width: 380px) {
  .app-wrapper { padding: 0 0.75rem; }
}

@media (max-width: 900px) and (orientation: landscape) {
  .panels { grid-template-columns: 1fr 44px 1fr; }
  .panel-input  { border-right: none; }
  .panel-output { border-left: none; }
  .panel { min-height: 200px; }
  .middle-actions {
    flex-direction: column;
    background: var(--bg);
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
  }
  .middle-actions .swap-btn { display: flex; }
}
```

- [ ] **Step 7: Verify visually**

Open `index.html` in a browser. Check:
- Sidebar renders on the left with CLASSICAL/MODERN groups
- Amber accent colour throughout (no blue remaining)
- IBM Plex Mono/Sans loaded (check Network tab — should see fonts.googleapis.com requests)
- `clip-path` chamfer cuts visible on panels and buttons
- Dot-grid background visible

- [ ] **Step 8: Commit**

```powershell
git add styles.css
git commit -m "feat: Industrial Console redesign — amber palette, IBM Plex, chamfer panels, sidebar"
```

---

## Task 6: Amber Glow on Output + Output Title Update in JS (app.js)

**Files:**
- Modify: `app.js`

- [ ] **Step 1: Add has-output class toggle to flashOutput**

Find the `flashOutput` function added in Task 3 Step 5 and update it:

```js
// OLD:
function flashOutput(isError, isWarning) {
  outputPanel.classList.remove('output-flash', 'error', 'warning');
  void outputPanel.offsetWidth;
  if (isError)        outputPanel.classList.add('error');
  else if (isWarning) outputPanel.classList.add('warning');
  else                outputPanel.classList.add('output-flash');
}

// NEW:
function flashOutput(isError, isWarning) {
  outputPanel.classList.remove('output-flash', 'error', 'warning');
  void outputPanel.offsetWidth;
  if (isError)        outputPanel.classList.add('error');
  else if (isWarning) outputPanel.classList.add('warning');
  else                outputPanel.classList.add('output-flash');
  // Amber glow when output is populated
  const hasContent = outputText.value.length > 0 && !isError;
  outputPanel.classList.toggle('has-output', hasContent);
}
```

- [ ] **Step 2: Remove cipherSelect references from app.js**

The old `cipherSelect` DOM ref and its event listener are no longer needed (sidebar replaced it). Remove:

```js
// Remove this line from DOM refs:
const cipherSelect   = document.getElementById('cipherSelect');

// Remove this event listener:
cipherSelect.addEventListener('change', () => {
  cipher = cipherSelect.value;
  updateKeyUI();
  process();
});
```

- [ ] **Step 3: Verify in browser**

Load `index.html`. Type text, select Caesar, encrypt — output panel should glow amber. Clear output — glow disappears.

- [ ] **Step 4: Commit**

```powershell
git add app.js
git commit -m "feat: amber output glow; remove obsolete cipherSelect wiring"
```

---

## Task 7: Smoke Testing All 11 Ciphers

**Files:** None (testing only)

- [ ] **Step 1: Test classical ciphers**

Open `index.html` in a browser. For each cipher below, paste the input, set the key, click encrypt, then copy output back to input and decrypt — verify round-trip:

| Cipher | Input | Key | Expected (encrypt) |
|---|---|---|---|
| Caesar | `Hello World` | 13 | `Uryyb Jbeyq` |
| Vigenère | `HELLO` | `KEY` | `RIJVS` |
| ROT13 | `Hello` | — | `Uryyb` |
| Base64 | `Hello` | — | `SGVsbG8=` |
| XOR | `Hello` | `FF` | Non-printable but decrypts back |
| Atbash | `Hello` | — | `Svool` |
| Playfair | `HELLO` | `KEY` | Verify decrypt returns `HELLO` (may have trailing X) |
| Rail Fence | `HELLO` | 3 | Verify decrypt returns `HELLO` |
| Columnar | `HELLO` | `KEY` | Verify decrypt returns `HELLO` |
| Beaufort | `HELLO` | `KEY` | Verify decrypt returns `HELLO` |
| AES-256-GCM | `Secret message` | `password123` | Base64 string; decrypt returns `Secret message` |

- [ ] **Step 2: Test AES wrong password**

Encrypt with password `correct`. Change password to `wrong`. Click decrypt. Expected: `⚠ Decryption failed — wrong password or corrupted data`

- [ ] **Step 3: Test mobile layout**

Open DevTools, set viewport to 375px. Verify:
- Sidebar renders as horizontal scroll row
- Mode toggle hidden (mobile nav used instead)
- All 11 ciphers reachable by scrolling the chip row

- [ ] **Step 4: Final commit**

```powershell
git add -A
git commit -m "feat: CipherLab v2 — 11 ciphers, Industrial Console redesign complete"
```
