// Run the conformance vectors against the JavaScript verifier: node tools/run_vectors.js
// Prints one line per failure and exits 1 if there are any. Kinds the verifier does not implement are skipped.
const fs = require("fs");
const path = require("path");
const PZ = require("../docs/verify/verify.js");

const dir = process.argv[2] || path.join(__dirname, "..", "patient_zero", "data", "vectors");
const hexOf = (b) => PZ.hex(b);

const checks = {
  "canonical-json": async (c) => (hexOf(PZ.canonical(c.value)) === c.canonical_hex ? null : "canonical bytes differ"),
  merkle: async (c) => {
    const leaves = c.leaves_hex.map(PZ.unhex);
    if (PZ.merkleRoot(leaves) !== c.root) return "root differs";
    for (let i = 0; i < leaves.length; i++) if (!PZ.verifyInclusion(leaves[i], c.root, c.proofs[i])) return `proof ${i} does not verify`;
    return null;
  },
  ed25519: async (c) => ((await PZ.verifySignature(PZ.unhex(c.message_hex), c.signature, c.public_key)) === c.valid ? null : "verify differs"),
  seal: async (c) => {
    const { problems } = await PZ.verifyBundle(c.bundle);
    const got = [...new Set(problems.map((p) => p.kind))].sort();
    return JSON.stringify(got) === JSON.stringify(c.errors) ? null : `errors ${JSON.stringify(got)}, expected ${JSON.stringify(c.errors)}`;
  },
};

(async () => {
  let failures = 0, ran = 0;
  for (const file of fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort()) {
    const doc = JSON.parse(fs.readFileSync(path.join(dir, file), "utf8"));
    const check = checks[doc.kind];
    if (!check) continue;
    for (const c of doc.cases) {
      ran++;
      const problem = await check(c);
      if (problem) { failures++; console.log(`${doc.kind} / ${c.name}: ${problem}`); }
    }
  }
  console.log(failures ? `${failures} of ${ran} vectors failed` : `CONFORMS: ${ran} vectors reproduced (canonical JSON, Merkle, Ed25519, seal)`);
  process.exit(failures ? 1 : 0);
})();
