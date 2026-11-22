/* Page logic for the verifier. All checking happens in verify.js, in this browser. */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (tag, text, cls) => { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; };
  let last = null;   // the files most recently chosen, so the key box can re-run the check

  const readBytes = (file) => file.arrayBuffer().then((b) => new Uint8Array(b));
  const asJson = (bytes) => { try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch (e) { return null; } };

  async function run(fileList) {
    const files = [];
    for (const f of fileList) files.push({ name: f.name, path: (f.webkitRelativePath || f.name).replace(/\\/g, "/"), bytes: await readBytes(f) });
    last = files;
    const expect = $("expect").value.trim();
    const parsed = files.map((f) => Object.assign({ json: f.bytes.length < 64 * 1024 * 1024 ? asJson(f.bytes) : null }, f));
    const bundle = parsed.find((f) => f.json && f.json.schema === PZ.BUNDLE);
    const seal = parsed.find((f) => f.json && f.json.head && f.json.items);
    const proof = parsed.find((f) => f.json && f.json.head && f.json.item && f.json.proof);
    let outcome, mode;
    if (bundle) { outcome = await PZ.verifyBundle(bundle.json, expect); mode = "bundle"; }
    else if (seal) {
      // Loose files: match each sealed path to a chosen file by the longest matching path ending.
      const map = {};
      for (const item of seal.json.items || []) {
        const hit = parsed.filter((f) => f !== seal && (f.path === item.path || f.path.endsWith("/" + item.path) || item.path.endsWith("/" + f.name) || item.path === f.name))
          .sort((a, b) => b.path.length - a.path.length)[0];
        if (hit) map[item.path] = hit.bytes;
      }
      outcome = await PZ.verifySeal(seal.json, map, expect); outcome.files = map; mode = "seal";
    } else if (proof) {
      const other = parsed.find((f) => f !== proof);
      if (!other) return show({ problems: [{ kind: "file", text: "Choose the proof together with the one file it is about." }], document: {} }, "proof");
      outcome = await PZ.verifyProof(proof.json, other.bytes, expect); outcome.files = { [proof.json.item.path]: other.bytes }; mode = "proof";
    } else {
      outcome = { problems: [{ kind: "signature", text: "None of these files is a patient-zero bundle, seal or proof." }], document: {} };
    }
    show(outcome, mode);
  }

  function show(outcome, mode) {
    const { problems, document: doc } = outcome;
    const head = (doc && doc.head) || {};
    $("result").hidden = false;
    $("again").hidden = false;
    const ok = problems.length === 0;
    $("verdict").className = "verdict " + (ok ? "ok" : "bad");
    $("verdict").textContent = ok
      ? (mode === "proof" ? "This file is part of what was signed, and has not been changed." : "Unchanged since it was signed.")
      : "Do not rely on this. It did not pass the check.";
    $("problems").replaceChildren(...problems.map((p) => el("li", p.text)));
    const notes = $("notes"); notes.replaceChildren();
    $("claims").hidden = !ok;
    if (!ok) return;

    const days = PZ.ageDays(head.sealed_at);
    if (days !== null && days > 365) notes.append(el("p", `This was signed ${PZ.agePhrase(days)}. Products change. Ask the vendor for a current one.`, "note"));
    else if (days !== null && days > 180) notes.append(el("p", `This was signed ${PZ.agePhrase(days)}. Ask whether the product has changed since.`, "note"));
    if (!$("expect").value.trim()) notes.append(el("p", "You have not said which key you expected. The check shows the files match the key inside them; see \"Who signed it\" for how to tie that key to the vendor.", "note"));

    const facts = $("facts"); facts.replaceChildren();
    const fact = (k, v) => { if (v) { facts.append(el("dt", k), el("dd", v)); } };
    fact("Product", head.product);
    fact("Level claimed", ({ L0: "L0: the product keeps patient data out", L1: "L1: stores and processes patient data", L2: "L2: AI agents act on patient data" })[head.level] || head.level);
    fact("Signed", `${PZ.agePhrase(days)} (${head.sealed_at})`);
    const s = head.summary;
    fact("Version tested", s && s.build);
    fact("Rulebook version", head.profile_version && `profile ${head.profile_version}`);

    const summary = $("summary"); summary.replaceChildren();
    if (s) {
      const box = el("div", undefined, "counts");
      const count = (n, label) => { const c = el("div", undefined, "count"); c.append(el("b", String(n)), el("span", label)); box.append(c); };
      count(`${s.confirmed} of ${s.controls}`, "safeguards confirmed by a person");
      count(s.confirmed_by_independent, "of those, confirmed by someone independent of the vendor");
      count(s.tested_clean_only, "tested by software and found clean, not confirmed by a person");
      count(s.failed, "failing a test");
      count(s.not_assessed, "not looked at yet");
      summary.append(el("h2", "What it says, in numbers"), box);
      if (s.failed > 0) summary.append(el("p", `${s.failed} safeguard${s.failed === 1 ? " is" : "s are"} failing. Ask the vendor which, and when it will be fixed.`, "note"));
      if (s.confirmed < s.controls - s.not_applicable) summary.append(el("p", "Not every safeguard is confirmed. That is normal for an honest report; ask what the plan is for the rest."));
    } else {
      summary.append(el("p", "This seal was made by an older version and carries no summary. Open the assessment file below to see what it claims."));
    }

    const signers = $("signers"); signers.replaceChildren();
    const signerCard = (title, signer, extra) => {
      const d = el("dl");
      const row = (k, v) => { if (v) d.append(el("dt", k), el("dd", v)); };
      row(title, signer.name || "(no name given)");
      row("Key", signer.public_key); d.lastChild.className = "mono";
      if (extra) row("They say", extra);
      const wrap = el("div"); wrap.style.marginBottom = "14px"; wrap.append(d);
      if (signer.domain) {
        const url = `https://${signer.domain}/.well-known/patient-zero.json`;
        const p = el("p"); p.append("Claims to be ", el("strong", signer.domain), ". ");
        const btn = el("button", `Check that ${signer.domain} lists this key`);
        const out = el("span"); out.style.marginLeft = "8px";
        btn.addEventListener("click", async () => {
          out.textContent = "Checking...";
          try {
            const r = await fetch(url, { cache: "no-store", credentials: "omit" });
            const problem = PZ.checkIdentity(await r.json(), signer.domain, signer.public_key);
            out.textContent = problem || `Yes. ${signer.domain} lists this key as its own.`;
          } catch (e) {
            out.textContent = ""; out.append("This page could not read it from here. Open ", Object.assign(el("a", url), { href: url, rel: "noopener", target: "_blank" }), " yourself and look for the key above.");
          }
        });
        p.append(btn, out); wrap.append(p);
      } else {
        wrap.append(el("p", "Names no website. The key shows the same party signed each report, not who that party is. Ask the vendor to publish their key on their own website.", "note"));
      }
      signers.append(wrap);
    };
    signerCard("Signed by", head.signer || {});
    for (const c of doc.cosignatures || []) {
      const role = { "independent-assessor": "Independent assessor", customer: "Customer", counsel: "Legal counsel", "internal-reviewer": "Internal reviewer" }[c.body.role] || c.body.role;
      signerCard(`Co-signed by (${role})`, c.body.signer || {}, c.body.statement);
    }
    if (!(doc.cosignatures || []).length) signers.append(el("p", "Nobody else has co-signed. Everything here is the vendor's own account."));

    const list = $("files"); list.replaceChildren();
    $("filesTitle").textContent = mode === "proof" ? "The file" : `The ${head.item_count} files`;
    for (const [path, bytes] of Object.entries(outcome.files || {})) {
      const link = el("a", path); link.href = URL.createObjectURL(new Blob([bytes])); link.download = path.split("/").pop();
      const li = el("li"); li.append(link, ` (${bytes.length.toLocaleString()} bytes)`); list.append(li);
    }
    if (mode === "proof") list.append(el("li", `One of ${head.item_count} sealed files. The others were not shared with you, and this proof does not reveal them.`));
  }

  const drop = $("drop"), pick = $("pick");
  drop.addEventListener("click", () => pick.click());
  drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick.click(); } });
  pick.addEventListener("change", () => pick.files.length && run(pick.files));
  ["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => e.dataTransfer.files.length && run(e.dataTransfer.files));
  $("again").addEventListener("click", () => last && run(last.map((f) => new File([f.bytes], f.name))));
  window.pzRun = run;   // for tests
})();
