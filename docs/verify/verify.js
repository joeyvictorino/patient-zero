/* patient-zero verifier: a second, independent implementation of seal verification.
 *
 * Runs in a browser (window.PZ) and in Node (module.exports). No dependencies, no
 * network. It reimplements what spec/SPEC.md requires: canonical JSON, BLAKE2b-256,
 * the Merkle tree, and strict Ed25519 verification. tests/test_verify_page.py runs it
 * against the same vectors the Python implementation has to pass.
 */
(function (root) {
  "use strict";

  // ---- bytes -----------------------------------------------------------------
  const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  const unhex = (text) => {
    if (typeof text !== "string" || text.length % 2 || /[^0-9a-f]/i.test(text)) throw new Error("not hex");
    const out = new Uint8Array(text.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(text.substr(i * 2, 2), 16);
    return out;
  };
  const concat = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) { out.set(p, at); at += p.length; }
    return out;
  };
  const unbase64 = (text) => {
    if (typeof atob === "function") return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
    return new Uint8Array(Buffer.from(text, "base64"));
  };
  const utf8 = (text) => new TextEncoder().encode(text);

  // ---- canonical JSON: sorted keys, no spaces, non-ASCII as \uXXXX ------------
  function canonical(value) {
    const walk = (v) => {
      if (v === null || typeof v === "string" || typeof v === "boolean") return JSON.stringify(v);
      if (typeof v === "number") {
        if (!Number.isInteger(v)) throw new Error("only integers may appear in signed data");
        return String(v);
      }
      if (Array.isArray(v)) return "[" + v.map(walk).join(",") + "]";
      if (typeof v === "object") {
        return "{" + Object.keys(v).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
          .map((k) => JSON.stringify(k) + ":" + walk(v[k])).join(",") + "}";
      }
      throw new Error("cannot canonicalize " + typeof v);
    };
    const text = walk(value).replace(/[\u007f-￿]/g, (c) =>
      c === "\u007f" ? c : "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
    return utf8(text);
  }

  // ---- BLAKE2b (RFC 7693), unkeyed, any digest size up to 64 bytes -----------
  const MASK = (1n << 64n) - 1n;
  const IV = [0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
    0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n];
  const SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4], [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13], [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11], [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5], [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]];
  const rotr = (x, n) => ((x >> n) | (x << (64n - n))) & MASK;

  function blake2b(data, size = 32) {
    const h = IV.slice();
    h[0] ^= 0x01010000n ^ BigInt(size);
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const compress = (block, counted, last) => {
      const m = new Array(16);
      for (let i = 0; i < 16; i++) m[i] = block.getBigUint64(i * 8, true);
      const v = h.concat(IV);
      v[12] ^= BigInt(counted) & MASK;
      if (last) v[14] ^= MASK;
      const G = (a, b, c, d, x, y) => {
        v[a] = (v[a] + v[b] + x) & MASK; v[d] = rotr(v[d] ^ v[a], 32n);
        v[c] = (v[c] + v[d]) & MASK; v[b] = rotr(v[b] ^ v[c], 24n);
        v[a] = (v[a] + v[b] + y) & MASK; v[d] = rotr(v[d] ^ v[a], 16n);
        v[c] = (v[c] + v[d]) & MASK; v[b] = rotr(v[b] ^ v[c], 63n);
      };
      for (let r = 0; r < 12; r++) {
        const s = SIGMA[r];
        G(0, 4, 8, 12, m[s[0]], m[s[1]]); G(1, 5, 9, 13, m[s[2]], m[s[3]]);
        G(2, 6, 10, 14, m[s[4]], m[s[5]]); G(3, 7, 11, 15, m[s[6]], m[s[7]]);
        G(0, 5, 10, 15, m[s[8]], m[s[9]]); G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(2, 7, 8, 13, m[s[12]], m[s[13]]); G(3, 4, 9, 14, m[s[14]], m[s[15]]);
      }
      for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
    };
    let offset = 0;
    while (data.length - offset > 128) {
      compress(new DataView(view.buffer, view.byteOffset + offset, 128), offset + 128, false);
      offset += 128;
    }
    const tail = new Uint8Array(128);
    tail.set(data.subarray(offset));
    compress(new DataView(tail.buffer), data.length, true);
    const out = new Uint8Array(64);
    const outView = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) outView.setBigUint64(i * 8, h[i], true);
    return out.subarray(0, size);
  }

  // ---- Merkle tree: leaf = H(00 || data), node = H(01 || l || r), odd node promoted
  const leafHash = (data) => blake2b(concat(Uint8Array.of(0), data));
  const nodeHash = (l, r) => blake2b(concat(Uint8Array.of(1), l, r));
  function merkleRoot(leaves) {
    let level = leaves.map(leafHash);
    if (!level.length) return hex(leafHash(new Uint8Array(0)));
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) next.push(i + 1 < level.length ? nodeHash(level[i], level[i + 1]) : level[i]);
      level = next;
    }
    return hex(level[0]);
  }
  function verifyInclusion(leaf, rootHex, proof) {
    try {
      let current = leafHash(leaf);
      for (const [side, siblingHex] of proof) {
        const sibling = unhex(siblingHex);
        if (sibling.length !== 32 || (side !== "L" && side !== "R")) return false;
        current = side === "L" ? nodeHash(sibling, current) : nodeHash(current, sibling);
      }
      return hex(current) === rootHex;
    } catch (e) { return false; }
  }

  // ---- Ed25519 verification (RFC 8032), strict ------------------------------
  const P = (1n << 255n) - 19n;
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  const mod = (a, m = P) => ((a % m) + m) % m;
  const pow = (base, exp, m = P) => {
    let result = 1n; base = mod(base, m);
    while (exp > 0n) { if (exp & 1n) result = (result * base) % m; base = (base * base) % m; exp >>= 1n; }
    return result;
  };
  const inv = (a) => pow(a, P - 2n);
  const D = mod(-121665n * inv(121666n));
  const I = pow(2n, (P - 1n) / 4n);
  const IDENTITY = [0n, 1n, 1n, 0n];
  function recoverX(y, sign) {
    const xx = mod((y * y - 1n) * inv(D * y * y + 1n));
    let x = pow(xx, (P + 3n) / 8n);
    if (mod(x * x - xx) !== 0n) x = mod(x * I);
    if (mod(x * x - xx) !== 0n || (x === 0n && sign)) throw new Error("invalid point");
    return (x & 1n) === BigInt(sign) ? x : P - x;
  }
  const BY = mod(4n * inv(5n));
  const BX = recoverX(BY, 0);
  const BASE = [BX, BY, 1n, mod(BX * BY)];
  function add(p, q) {
    const a = mod((p[1] - p[0]) * (q[1] - q[0])), b = mod((p[1] + p[0]) * (q[1] + q[0]));
    const c = mod(2n * D * p[3] * q[3]), d = mod(2n * p[2] * q[2]);
    const e = b - a, f = d - c, g = d + c, h = b + a;
    return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)];
  }
  function multiply(point, scalar) {
    let result = IDENTITY;
    while (scalar > 0n) { if (scalar & 1n) result = add(result, point); point = add(point, point); scalar >>= 1n; }
    return result;
  }
  const fromLE = (bytes) => bytes.reduceRight((n, b) => (n << 8n) | BigInt(b), 0n);
  function encode(point) {
    const zi = inv(point[2]);
    const x = mod(point[0] * zi), y = mod(point[1] * zi);
    let n = y | ((x & 1n) << 255n);
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) { out[i] = Number(n & 0xffn); n >>= 8n; }
    return out;
  }
  function decode(bytes) {
    if (bytes.length !== 32) throw new Error("point must be 32 bytes");
    const n = fromLE(bytes);
    const y = n & ((1n << 255n) - 1n), sign = Number(n >> 255n);
    if (y >= P) throw new Error("noncanonical point");
    const x = recoverX(y, sign);
    return [x, y, 1n, mod(x * y)];
  }
  async function sha512(bytes) {
    const subtle = (root.crypto || globalThis.crypto || {}).subtle;
    if (!subtle) throw new Error("this browser cannot compute SHA-512 here; open the page over https or from a file");
    return new Uint8Array(await subtle.digest("SHA-512", bytes));
  }
  async function verifySignature(payload, signatureHex, publicHex) {
    try {
      const sig = unhex(signatureHex), pub = unhex(publicHex);
      if (sig.length !== 64 || pub.length !== 32) return false;
      const s = fromLE(sig.subarray(32));
      if (s >= L) return false;
      const A = decode(pub), R = decode(sig.subarray(0, 32));
      const identity = hex(encode(IDENTITY));
      if (hex(pub) === identity || hex(encode(multiply(A, L))) !== identity) return false;
      if (hex(encode(multiply(R, L))) !== identity) return false;
      const k = fromLE(await sha512(concat(sig.subarray(0, 32), pub, payload))) % L;
      return hex(encode(multiply(BASE, s))) === hex(encode(add(R, multiply(A, k))));
    } catch (e) { return false; }
  }

  // ---- seals -----------------------------------------------------------------
  const SEAL = "patient-zero-seal-v1", COSIGN = "patient-zero-cosign-v1", BUNDLE = "patient-zero-bundle-v1";
  const leafOf = (item) => canonical({ path: item.path, blake2b_256: item.blake2b_256, bytes: item.bytes });

  async function checkHead(document, expectKey) {
    const problems = [];
    const head = (document && document.head) || {};
    if (head.schema !== SEAL) return [{ kind: "signature", text: "This is not a patient-zero seal, or it is a version this page does not know." }];
    const key = (head.signer || {}).public_key || "";
    if (!(await verifySignature(canonical(head), document.signature || "", key))) {
      problems.push({ kind: "signature", text: "The signature does not match. The signed statement was changed after signing, or was never signed by this key." });
    }
    if (expectKey && key !== expectKey.trim().toLowerCase()) {
      problems.push({ kind: "key", text: "It was signed by a different key than the one you expected." });
    }
    for (const entry of document.cosignatures || []) {
      const body = entry.body || {};
      const who = (body.signer || {}).name || "an unnamed co-signer";
      if (body.schema !== COSIGN) problems.push({ kind: "cosignature", text: `The co-signature by ${who} is in a format this page does not know.` });
      else if (body.merkle_root !== head.merkle_root || body.seal_signature !== document.signature) {
        problems.push({ kind: "cosignature", text: `The co-signature by ${who} was made over a different seal.` });
      } else if (!(await verifySignature(canonical(body), entry.signature || "", (body.signer || {}).public_key || ""))) {
        problems.push({ kind: "cosignature", text: `The co-signature by ${who} does not match.` });
      }
    }
    return problems;
  }

  /** files: Map or object of path -> Uint8Array. Returns {problems, document}. */
  async function verifySeal(document, files, expectKey) {
    const problems = await checkHead(document, expectKey);
    const head = document.head || {}, items = document.items || [];
    const get = (path) => (files instanceof Map ? files.get(path) : files[path]);
    if (items.length !== head.item_count || merkleRoot(items.map(leafOf)) !== head.merkle_root) {
      problems.push({ kind: "root", text: "The list of files does not match what was signed. A file was added to or removed from the list." });
    }
    for (const item of items) {
      const data = get(item.path);
      if (!data) problems.push({ kind: "file", text: `Missing: ${item.path}` });
      else if (data.length !== item.bytes || hex(blake2b(data)) !== item.blake2b_256) {
        problems.push({ kind: "file", text: `Changed since it was signed: ${item.path}` });
      }
    }
    return { problems, document };
  }

  async function verifyBundle(packed, expectKey) {
    if (!packed || packed.schema !== BUNDLE) return { problems: [{ kind: "signature", text: "This is not a patient-zero bundle." }], document: {} };
    const files = {};
    for (const [path, data] of Object.entries(packed.files || {})) {
      try { files[path] = unbase64(data); } catch (e) { /* reported as missing */ }
    }
    return Object.assign(await verifySeal(packed.seal || {}, files, expectKey), { files });
  }

  /** A proof that one file belongs to a seal, without the other files. */
  async function verifyProof(proof, fileBytes, expectKey) {
    const problems = await checkHead(proof, expectKey);
    const item = proof.item || {};
    if (fileBytes.length !== item.bytes || hex(blake2b(fileBytes)) !== item.blake2b_256) {
      problems.push({ kind: "file", text: "This file is not the one the proof is about, or it was changed." });
    }
    if (!verifyInclusion(leafOf(item), (proof.head || {}).merkle_root || "", proof.proof || [])) {
      problems.push({ kind: "root", text: "The proof does not lead to the signed seal." });
    }
    return { problems, document: proof };
  }

  function ageDays(sealedAt, now) {
    const then = Date.parse(sealedAt);
    return Number.isNaN(then) ? null : Math.max(0, Math.floor(((now || Date.now()) - then) / 86400000));
  }
  function agePhrase(days) {
    if (days === null) return "at an unknown time";
    if (days < 1) return "today";
    if (days < 60) return `${days} day${days === 1 ? "" : "s"} ago`;
    return `about ${Math.round(days / 30.44)} months ago`;
  }
  function checkIdentity(identity, domain, publicKey) {
    if (!identity || identity.schema !== "patient-zero-identity-v1") return `${domain} does not publish a patient-zero identity file.`;
    if (identity.domain !== domain) return `The identity file is for ${identity.domain}, not ${domain}.`;
    const key = (identity.keys || []).find((k) => k && k.public_key === publicKey);
    if (!key) return `${domain} does not list this key.`;
    return key.status === "active" ? "" : `${domain} lists this key as ${key.status}.`;
  }

  const api = { hex, unhex, utf8, canonical, blake2b, merkleRoot, verifyInclusion, verifySignature, verifySeal, verifyBundle,
    verifyProof, ageDays, agePhrase, checkIdentity, SEAL, BUNDLE };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.PZ = api;
})(typeof window !== "undefined" ? window : globalThis);
