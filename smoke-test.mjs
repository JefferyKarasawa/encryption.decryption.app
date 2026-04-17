/**
 * CipherLab Smoke Test — Task 7
 * Tests all synchronous cipher round-trips using the plan's expected values.
 * Run: node smoke-test.mjs
 */

// ─── Cipher implementations (copied from app.js for Node test) ───

function caesarEncrypt(text, shift) {
  return [...text].map(ch => {
    const latin = ch.match(/[a-zA-Z]/);
    if (latin) {
      const base = ch >= 'a' ? 97 : 65;
      return String.fromCharCode(((ch.charCodeAt(0) - base + shift) % 26) + base);
    }
    return ch;
  }).join('');
}
function caesarDecrypt(text, shift) { return caesarEncrypt(text, 26 - (shift % 26)); }

function vigenereEncrypt(text, key) {
  if (!key) return text;
  const k = [...key.replace(/[^a-zA-Z]/g, '').toUpperCase()];
  if (!k.length) return text;
  let ki = 0;
  return [...text].map(ch => {
    if (/[a-zA-Z]/.test(ch)) {
      const isUpper = ch === ch.toUpperCase();
      const base = isUpper ? 65 : 97;
      const shift = k[ki++ % k.length].charCodeAt(0) - 65;
      return String.fromCharCode(((ch.toUpperCase().charCodeAt(0) - 65 + shift) % 26) + base);
    }
    return ch;
  }).join('');
}
function vigenereDecrypt(text, key) {
  if (!key) return text;
  const k = [...key.replace(/[^a-zA-Z]/g, '').toUpperCase()];
  if (!k.length) return text;
  let ki = 0;
  return [...text].map(ch => {
    if (/[a-zA-Z]/.test(ch)) {
      const isUpper = ch === ch.toUpperCase();
      const base = isUpper ? 65 : 97;
      const shift = k[ki++ % k.length].charCodeAt(0) - 65;
      return String.fromCharCode(((ch.toUpperCase().charCodeAt(0) - 65 - shift + 26) % 26) + base);
    }
    return ch;
  }).join('');
}

function rot13(text) {
  return [...text].map(ch => {
    if (/[a-zA-Z]/.test(ch)) {
      const base = ch >= 'a' ? 97 : 65;
      return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base);
    }
    return ch;
  }).join('');
}

function atbash(text) {
  return [...text].map(ch => {
    if (/[a-zA-Z]/.test(ch)) {
      const base = ch >= 'a' ? 97 : 65;
      return String.fromCharCode(base + 25 - (ch.charCodeAt(0) - base));
    }
    return ch;
  }).join('');
}

function base64Encode(text) { return Buffer.from(text, 'utf8').toString('base64'); }
function base64Decode(text) {
  try { return Buffer.from(text, 'base64').toString('utf8'); } catch { return null; }
}

function xorCipher(text, hexKey) {
  if (!hexKey) return text;
  const key = hexKey.replace(/[^0-9a-fA-F]/g, '');
  if (!key.length) return text;
  const keyBytes = key.match(/.{1,2}/g).map(b => parseInt(b, 16));
  return [...text].map((ch, i) => String.fromCharCode(ch.charCodeAt(0) ^ keyBytes[i % keyBytes.length])).join('');
}

function playfairBuildGrid(key) {
  const seen = new Set();
  const grid = [];
  const clean = (key.toUpperCase() + 'ABCDEFGHIKLMNOPQRSTUVWXYZ').replace(/[^A-Z]/g, '');
  for (const ch of clean) {
    const c = ch === 'J' ? 'I' : ch;
    if (!seen.has(c)) { seen.add(c); grid.push(c); }
  }
  return grid;
}
function playfairPos(grid, ch) {
  const idx = grid.indexOf(ch === 'J' ? 'I' : ch);
  return [Math.floor(idx / 5), idx % 5];
}
function playfairProcess(text, key, encrypt) {
  const grid = playfairBuildGrid(key || 'KEY');
  const dir = encrypt ? 1 : -1;
  const positions = [];
  const letters = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i].toUpperCase();
    if (/[A-Z]/.test(ch)) {
      letters.push(ch === 'J' ? 'I' : ch);
    } else {
      positions.push({ idx: i, ch: text[i] });
    }
  }
  const bigrams = [];
  let i = 0;
  while (i < letters.length) {
    const a = letters[i];
    const b = letters[i + 1];
    if (b === undefined) { bigrams.push([a, 'X']); i++; }
    else if (a === b)    { bigrams.push([a, 'X']); i++; }
    else                 { bigrams.push([a, b]);   i += 2; }
  }
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
  const latinOut = result.map((ch, idx) => {
    const orig = letters[idx];
    return orig && orig === orig.toLowerCase() ? ch.toLowerCase() : ch;
  });
  return latinOut.join('') + positions.map(p => p.ch).join('');
}
function playfairEncrypt(text, key) { return playfairProcess(text, key, true); }
function playfairDecrypt(text, key) { return playfairProcess(text, key, false); }

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
  const counts = new Array(rails).fill(0);
  for (const r of indices) counts[r]++;
  const rows = [];
  let pos = 0;
  for (const c of counts) { rows.push([...text.slice(pos, pos + c)]); pos += c; }
  const rowIdx = new Array(rails).fill(0);
  return indices.map(r => rows[r][rowIdx[r]++]).join('');
}

function columnarEncrypt(text, key) {
  const k = (key || '').replace(/[^a-zA-Z]/g, '').toUpperCase();
  if (!k) return text;
  const cols = k.length;
  const rows = Math.ceil(text.length / cols);
  const padded = text.padEnd(rows * cols, '\0');
  const grid = [];
  for (let c = 0; c < cols; c++) {
    const col = [];
    for (let r = 0; r < rows; r++) col.push(padded[r * cols + c]);
    grid.push({ char: k[c], col, origIdx: c });
  }
  grid.sort((a, b) => a.char < b.char ? -1 : a.char > b.char ? 1 : a.origIdx - b.origIdx);
  return grid.flatMap(g => g.col).filter(c => c !== '\0').join('');
}
function columnarDecrypt(text, key) {
  const k = (key || '').replace(/[^a-zA-Z]/g, '').toUpperCase();
  if (!k) return text;
  const cols = k.length;
  const rows = Math.ceil(text.length / cols);
  const totalCells = rows * cols;
  const shortCols = totalCells - text.length;
  const order = [...k].map((char, origIdx) => ({ char, origIdx }));
  order.sort((a, b) => a.char < b.char ? -1 : a.char > b.char ? 1 : a.origIdx - b.origIdx);
  // Assign lengths by original column index (matching app.js logic)
  const lengths = new Array(cols);
  for (let i = 0; i < cols; i++) {
    lengths[order[i].origIdx] = (order[i].origIdx >= cols - shortCols) ? rows - 1 : rows;
  }
  const sortedCols = [];
  let pos = 0;
  for (const { origIdx } of order) {
    const len = lengths[origIdx];
    sortedCols.push({ origIdx, chars: [...text.slice(pos, pos + len)] });
    pos += len;
  }
  const cols2 = new Array(cols);
  for (const { origIdx, chars } of sortedCols) cols2[origIdx] = chars;
  const result = [];
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      if (cols2[c][r] !== undefined) result.push(cols2[c][r]);
    }
  }
  return result.join('');
}

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

// ─── Test Runner ─────────────────────────────────────────────

let passed = 0;
let failed = 0;

function check(label, actual, expected) {
  if (actual === expected) {
    console.log(`  ✅ ${label}`);
    passed++;
  } else {
    console.log(`  ❌ ${label}`);
    console.log(`     expected: ${JSON.stringify(expected)}`);
    console.log(`     actual:   ${JSON.stringify(actual)}`);
    failed++;
  }
}

function roundTrip(label, encrypt, decrypt, input) {
  const enc = encrypt(input);
  const dec = decrypt(enc);
  // Playfair may pad with X — strip trailing X for comparison
  const decNorm = dec.replace(/X+$/, '');
  const inputNorm = input.replace(/X+$/, '');
  if (dec === input || decNorm === inputNorm) {
    console.log(`  ✅ ${label} round-trip`);
    passed++;
  } else {
    console.log(`  ❌ ${label} round-trip`);
    console.log(`     input:    ${JSON.stringify(input)}`);
    console.log(`     enc:      ${JSON.stringify(enc)}`);
    console.log(`     dec:      ${JSON.stringify(dec)}`);
    failed++;
  }
}

console.log('\n═══ CipherLab Smoke Tests ═══\n');

// Caesar
console.log('Caesar:');
check('encrypt Hello World shift=13', caesarEncrypt('Hello World', 13), 'Uryyb Jbeyq');
check('decrypt Uryyb Jbeyq shift=13', caesarDecrypt('Uryyb Jbeyq', 13), 'Hello World');
roundTrip('Caesar shift=7', t => caesarEncrypt(t, 7), t => caesarDecrypt(t, 7), 'The Quick Brown Fox');

// Vigenère
console.log('\nVigenère:');
check('encrypt HELLO key=KEY', vigenereEncrypt('HELLO', 'KEY'), 'RIJVS');
check('decrypt RIJVS key=KEY', vigenereDecrypt('RIJVS', 'KEY'), 'HELLO');
roundTrip('Vigenere', t => vigenereEncrypt(t, 'SECRET'), t => vigenereDecrypt(t, 'SECRET'), 'Hello World');

// ROT13
console.log('\nROT13:');
check('encrypt Hello', rot13('Hello'), 'Uryyb');
check('symmetric: rot13(rot13(x)) === x', rot13(rot13('Hello World 123')), 'Hello World 123');

// Atbash
console.log('\nAtbash:');
check('encrypt Hello', atbash('Hello'), 'Svool');
check('symmetric: atbash(atbash(x)) === x', atbash(atbash('Hello World')), 'Hello World');

// Base64
console.log('\nBase64:');
check('encode Hello', base64Encode('Hello'), 'SGVsbG8=');
check('decode SGVsbG8=', base64Decode('SGVsbG8='), 'Hello');
roundTrip('Base64', base64Encode, base64Decode, 'Hello, World! 日本語テスト');

// XOR
console.log('\nXOR:');
roundTrip('XOR key=FF', t => xorCipher(t, 'FF'), t => xorCipher(t, 'FF'), 'Hello');
roundTrip('XOR key=A3F2', t => xorCipher(t, 'A3F2'), t => xorCipher(t, 'A3F2'), 'Hello World');

// Playfair
console.log('\nPlayfair:');
const pfEnc = playfairEncrypt('HELLO', 'KEY');
const pfDec = playfairDecrypt(pfEnc, 'KEY');
// HELLO has double-L → bigrams [HE][LX][LO] → decrypt → HELXLO (X between Ls is correct Playfair behavior)
check('encrypt then decrypt HELLO (double-L gets X inserted: HELXLO)', pfDec, 'HELXLO');
// No-double-letter input round-trips cleanly
roundTrip('Playfair no doubles round-trip', t => playfairEncrypt(t, 'KEY'), t => playfairDecrypt(t, 'KEY'), 'CIPHERTEXT');
roundTrip('Playfair longer', t => playfairEncrypt(t, 'CIPHER'), t => playfairDecrypt(t, 'CIPHER'), 'ATTACKATDAWN');

// Rail Fence
console.log('\nRail Fence:');
roundTrip('Rail Fence rails=3', t => railFenceEncrypt(t, 3), t => railFenceDecrypt(t, 3), 'HELLO');
roundTrip('Rail Fence rails=2', t => railFenceEncrypt(t, 2), t => railFenceDecrypt(t, 2), 'WEAREDISCOVEREDFLEEAATONCE');

// Columnar Transposition
console.log('\nColumnar Transposition:');
roundTrip('Columnar key=KEY', t => columnarEncrypt(t, 'KEY'), t => columnarDecrypt(t, 'KEY'), 'HELLO');
roundTrip('Columnar longer', t => columnarEncrypt(t, 'ZEBRAS'), t => columnarDecrypt(t, 'ZEBRAS'), 'WEAREDISCOVEREDFLEEAATONCE');

// Beaufort
console.log('\nBeaufort:');
const bfEnc = beaufort('HELLO', 'KEY');
const bfDec = beaufort(bfEnc, 'KEY');
check('symmetric: beaufort(beaufort(HELLO,KEY),KEY) === HELLO', bfDec, 'HELLO');
roundTrip('Beaufort longer', t => beaufort(t, 'SECRET'), t => beaufort(t, 'SECRET'), 'HELLOWORLD');

console.log(`\n═══ Results: ${passed} passed, ${failed} failed ═══\n`);
process.exit(failed > 0 ? 1 : 0);
