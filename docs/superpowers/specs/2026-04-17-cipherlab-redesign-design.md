# CipherLab — Redesign & Cipher Expansion Design Spec
**Date:** 2026-04-17  
**Status:** Approved

---

## 1. Goals

1. Add 5 new cipher algorithms (4 classical, 1 modern) to raise the total from 6 → 11.
2. Redesign the UI from a generic dark dashboard into an intentional **Industrial Console** aesthetic.
3. Keep all processing 100% client-side; no external API calls or data transmission.

---

## 2. Cipher Architecture

### 2.1 Retained Ciphers (logic unchanged)
| Cipher | Notes |
|---|---|
| Caesar | Supports Latin, Hiragana/Katakana, Kanji |
| Vigenère | Multi-script |
| ROT13 | Symmetric; ROT43 for Japanese |
| Base64 | Encoding, not security cipher |
| XOR | Hex key input |
| Atbash | Multi-script mirror |

### 2.2 New Classical Ciphers (pure JS, synchronous)

#### Playfair
- 5×5 keyword grid, bigram substitution, Latin only.
- `J` merged into `I` (standard Playfair convention).
- Key: text keyword (max 25 Latin chars, duplicates removed).
- Non-Latin characters pass through unchanged.
- Odd-length plaintexts get `X` appended before processing.
- Digraph padding: if both chars in a pair are identical, replace second with `X`.

#### Rail Fence
- Zigzag transposition across N rails.
- Key: integer 2–10. Values outside range clamped silently to nearest bound.
- Works on full Unicode; purely positional.
- Encrypt: write diagonal, read rows. Decrypt: reconstruct rail lengths, read diagonals.

#### Columnar Transposition
- Write plaintext in rows; read columns in keyword-alphabetical order.
- Key: text keyword (max 20 chars). Non-alphabetic key characters stripped. Empty key → identity (no-op).
- Works on full Unicode content; only the key needs to be alphabetic.

#### Beaufort
- Reciprocal Vigenère variant: `ciphertext = (key[i] - plaintext[i] + 26) mod 26`.
- Symmetric: same operation encrypts and decrypts.
- Latin only (A–Z, a–z). Non-Latin chars pass through.
- Key: text keyword (max 64 chars, Latin only used for shifts).

### 2.3 New Modern Cipher (async, Web Crypto API)

#### AES-256-GCM
- **Key derivation:** PBKDF2, SHA-256, 310,000 iterations, 32-byte output (256-bit key).
- **Per-encrypt randomness:** 16-byte salt (for PBKDF2) + 12-byte IV (for GCM), generated via `crypto.getRandomValues()`.
- **Ciphertext format:** `base64(salt[16 bytes] || iv[12 bytes] || ciphertext || GCM auth tag[16 bytes])`.
- **Decrypt:** parse same format; GCM auth tag mismatch throws and surfaces as user-friendly error.
- **Input:** password field with show/hide toggle and password-strength indicator (entropy bits: `length × log2(charset_size)`).
- **UI contract:** operation is async; during processing the middle arrow/spinner area switches to a spinning indicator; output clears and shows `⟳ Processing…` until done.
- **Security context:** if `window.crypto.subtle` is unavailable, surface `⚠ AES requires a secure context (HTTPS or localhost)`.
- **No server communication** of any kind.

---

## 3. UI Architecture

### 3.1 Layout

```
┌────────────────────────────────────────────────────────┐
│  HEADER: logo · tagline · theme toggle · install btn   │
├──────────────┬─────────────────────────────────────────┤
│  CIPHER      │  KEY PARAMETERS panel                   │
│  SIDEBAR     ├──────────┬──────────────────────────────┤
│  (left)      │  INPUT   │  OUTPUT                      │
│              │  panel   │  panel                       │
│              ├──────────┴──────────────────────────────┤
│              │  INFO BAR                               │
├──────────────┴─────────────────────────────────────────┤
│  FOOTER: "All processing is local…"                    │
└────────────────────────────────────────────────────────┘
```

- Sidebar is **220px wide** on desktop, collapses to a horizontal scrollable chip row on mobile (≤768px).
- The two text panels split the remaining width equally.
- A **middle-actions column (40px)** sits between input and output panels containing the mode arrow/spinner and swap button.

### 3.2 Cipher Sidebar
- Two group headers: `── CLASSICAL ──` and `── MODERN ──`
- Each cipher entry: icon (16px SVG) + cipher name in IBM Plex Mono.
- Active cipher: amber (`#e8a030`) left-border (3px) + slightly raised background.
- Non-active hover: subtle background lift.
- Clicking a cipher updates the key parameters panel and re-runs process.

### 3.3 Mode Toggle
- Two buttons `[ ENCRYPT ]` / `[ DECRYPT ]` in monospace uppercase.
- A sliding amber underline (150ms CSS `transform: translateX`) moves between the two.
- No filled background on the active button; underline is the sole active indicator.

### 3.4 Key Parameters Panel
- Sits above the input/output panels.
- Label: `── KEY PARAMETERS ──` in monospace.
- Shows the relevant input for the selected cipher (see Section 2 table).
- AES password field includes:
  - Show/hide toggle button (eye icon).
  - Entropy strength bar (4 segments: Weak / Fair / Good / Strong) computed live.

### 3.5 Panel Details
- Panel corners: `clip-path` 6px chamfer cut (`polygon(6px 0, 100% 0, 100% calc(100% - 6px), calc(100% - 6px) 100%, 0 100%, 0 6px)`).
- Panel header separators: `──────────` ruled lines in amber/dim color.
- Active output panel: faint amber `box-shadow` glow when output is non-empty.
- Background texture: repeating dot-grid via `radial-gradient(circle, #1e2535 1px, transparent 1px)` at 20px spacing.

---

## 4. Visual Design Tokens

| Token | Value |
|---|---|
| `--bg` | `#0b0d11` |
| `--bg-raised` | `#111520` |
| `--bg-panel` | `#111520` |
| `--bg-panel-alt` | `#161b27` |
| `--bg-hover` | `#1a2030` |
| `--border` | `#1e2535` |
| `--border-mid` | `#2a3347` |
| `--border-focus` | `#e8a030` |
| `--accent` | `#e8a030` |
| `--accent-dim` | `#c07820` |
| `--text-hi` | `#d4cfc8` |
| `--text-mid` | `#7a8099` |
| `--text-lo` | `#3a4055` |
| `--success` | `#3db87a` |
| `--error` | `#e05555` |
| `--warn` | `#d4a017` |
| `--font-mono` | `'IBM Plex Mono', monospace` |
| `--font-sans` | `'IBM Plex Sans', sans-serif` |

Light theme retains its own overrides for `--bg`, `--bg-raised`, `--bg-panel`, `--bg-panel-alt`, `--bg-hover`, `--border`, `--border-mid`, `--text-hi`, `--text-mid`, `--text-lo`.

---

## 5. Micro-Interactions & Motion

| Trigger | Effect |
|---|---|
| New output generated | Amber pulse on output panel (replaces current blue flash) |
| Copy success | Amber fill on copy button for 2s, then revert |
| Mode switch | 150ms `transform: translateX` on amber underline indicator |
| AES processing | Arrow icon replaced by CSS spinner; output shows `⟳ Processing…` |
| Sidebar cipher select | Active item transitions background in 100ms |
| Input/output flash error | Red border pulse on output panel (unchanged) |

---

## 6. Error Handling

| Scenario | Displayed message |
|---|---|
| AES wrong password / corrupted data | `⚠ Decryption failed — wrong password or corrupted data` |
| AES no secure context | `⚠ AES requires a secure context (HTTPS or localhost)` |
| Base64 invalid input | `⚠ Invalid Base64 input` (unchanged) |
| Input > 500KB | `⚠ Input too large (max 500 KB)` (unchanged) |
| Rail Fence key out of range | Silently clamped to 2–10, no message |
| Columnar empty/invalid key | Falls back to identity (text returned as-is) |
| Playfair non-Latin chars | Passed through unchanged |

---

## 7. Cipher Info Descriptions (new entries)

```
playfair:   "Playfair uses a 5×5 keyword grid for bigram substitution. J is merged into I. Non-Latin characters pass through unchanged. Odd-length input is padded with X."
railfence:  "Rail Fence writes text diagonally across N rails, then reads row by row. Key is the number of rails (2–10). Works on any Unicode text."
columnar:   "Columnar Transposition writes text in rows, then reads columns in keyword-alphabetical order. Non-alphabetic key characters are ignored."
beaufort:   "Beaufort cipher: ciphertext = (key − plaintext) mod 26. Reciprocal — the same key and operation both encrypts and decrypts. Latin only."
aes256gcm:  "AES-256-GCM with PBKDF2 key derivation (310,000 iterations, SHA-256). Authenticated encryption — wrong passwords are detected. 100% local processing."
```

---

## 8. File Structure (no new files added)

All changes contained in the three existing files:

| File | Changes |
|---|---|
| `app.js` | Add 5 cipher implementations; update `process()`, `updateKeyUI()`, `CIPHER_INFO`; add AES async handling |
| `index.html` | Replace cipher `<select>` with sidebar markup; update key input panel; update mode toggle markup; add AES password strength UI |
| `styles.css` | Full token swap; sidebar styles; mode underline indicator; chamfer clip-paths; dot-grid texture; amber pulse animation; AES spinner |

`sw.js` and `manifest.json` require no changes.

---

## 9. Out of Scope

- No framework migration (stays vanilla HTML/CSS/JS).
- No file encryption/decryption (text only).
- No server-side component.
- No new cipher beyond the 5 specified.
- No analytics or telemetry.
