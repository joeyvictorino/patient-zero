"""pz: the patient-zero command line."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import (
    __version__,
    assess,
    auditlog,
    badge as badge_mod,
    bayes,
    buyer,
    check as check_mod,
    coverage,
    hidden,
    html,
    nevada,
    phi,
    profile as profile_mod,
    replay as replay_mod,
    report,
    seal as seal_mod,
)
from .probes import ProbeRefused, load_target, write_evidence
from .probes import agent as agent_probe
from .probes import claims as claims_probe
from .probes import restore as restore_probe
from .probes import rls as rls_probe
from .probes import stack as stack_probe
from .probes import isolation as isolation_probe
from .probes import offline as offline_probe
from .probes import tls as tls_probe

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2
PROBES = ["isolation", "agent", "egress", "tls", "log", "stack", "rls", "claims", "restore"]


def _cmd_controls(args) -> int:
    prof = profile_mod.load(args.profile)
    if args.validate:
        print(f"profile {prof.version}: {len(prof.controls)} controls in {len(prof.families)} families, valid")
        return EXIT_OK
    if args.markdown:
        sys.stdout.write(coverage.profile_markdown(prof))
        return EXIT_OK
    controls = prof.for_level(args.level) if args.level else prof.controls
    if args.family:
        controls = [c for c in controls if c.family == args.family.upper()]
    if args.json:
        print(json.dumps([c.__dict__ for c in controls], indent=2))
    else:
        for c in controls:
            print(f"{c.id:<8} {c.min_level}  {c.statement}")
        print(f"\n{len(controls)} controls")
    return EXIT_OK


def _cmd_coverage(args) -> int:
    prof = profile_mod.load(args.profile)
    if args.markdown:
        sys.stdout.write(coverage.markdown(prof))
        return EXIT_OK
    if args.json:
        print(json.dumps({"summary": coverage.summary(prof), "controls": coverage.rows(prof)}, indent=2))
        return EXIT_OK
    for r in coverage.rows(prof):
        print(f"{r['id']:<8} {r['support']:<26} {', '.join(r['probes'] + r['safeguards'])}")
    s = coverage.summary(prof)
    print(f"\n{s['probes']} probes touch {s['probed']} of {s['controls']} controls; {s['with_reference_code']} have reference code; "
          f"{s['manual_only']} are manual only")
    return EXIT_OK


def _cmd_questionnaire(args) -> int:
    sys.stdout.write(buyer.questionnaire(profile_mod.load(args.profile), args.level, args.overlay))
    return EXIT_OK


def _cmd_overlay(args) -> int:
    if args.review:
        sys.stdout.write(buyer.overlay_review(args.name))
        return EXIT_OK
    if args.markdown:
        sys.stdout.write(buyer.overlay_markdown(args.name))
        return EXIT_OK
    data = buyer.load_overlay(args.name)
    for item in data["items"]:
        print(f"{item['id']:<6} {item['law']} {item['cite']:<12} {item['plain']}")
    return EXIT_OK


def _cmd_init(args) -> int:
    prof = profile_mod.load(args.profile)
    data = assess.new(args.product, args.level, prof)
    assess.save(data, args.output)
    print(f"wrote {args.output}: {len(data['controls'])} controls required at {args.level}")
    return EXIT_OK


def _cmd_set(args) -> int:
    data = assess.load(args.assessment)
    assess.set_status(data, args.control.upper(), args.status, args.note or "", args.evidence or [], args.assessor,
                      independent=args.independent)
    assess.save(data, args.assessment)
    print(f"{args.control.upper()} set to {args.status}")
    return EXIT_OK


def _finish_probe(result, args) -> int:
    path = write_evidence(result, args.evidence_dir)
    print(f"{result.probe}: {result.checks} checks, {len(result.findings)} findings, {len(result.inconclusive)} inconclusive")
    if result.void:
        print("  VOID: no check in this run could have found a problem. This is not a clean result.")
    for line in result.grouped():
        print(f"  {line}")
    for note in result.inconclusive:
        print(f"  [note] {note}")
    print(f"evidence: {path}")
    if args.assessment:
        data = assess.load(args.assessment)
        touched = assess.apply_probe(data, result, path)
        assess.save(data, args.assessment)
        print(f"assessment updated: {', '.join(touched) if touched else 'no controls at this level'}")
    return EXIT_OK if result.clean else EXIT_FINDINGS


def _cmd_probe(args) -> int:
    if args.name == "log":
        if not args.file:
            print("pz probe log needs --file", file=sys.stderr)
            return EXIT_USAGE
        return _finish_probe(offline_probe.run_log(args.file, args.expected_head), args)
    if args.name == "stack":
        return _finish_probe(stack_probe.run(args.path), args)
    if args.name == "rls":
        return _finish_probe(rls_probe.run(args.path), args)
    if args.name == "restore":
        if not args.manifest:
            print("pz probe restore needs --manifest and --path", file=sys.stderr)
            return EXIT_USAGE
        return _finish_probe(restore_probe.run(args.manifest, args.path), args)
    if args.name == "claims":
        if not args.file or not args.transcript:
            print("pz probe claims needs --transcript and --file", file=sys.stderr)
            return EXIT_USAGE
        return _finish_probe(claims_probe.run(args.transcript, args.file), args)
    if not args.config:
        print(f"pz probe {args.name} needs --config target.yaml", file=sys.stderr)
        return EXIT_USAGE
    target = load_target(args.config)
    runner = {
        "isolation": isolation_probe.run,
        "agent": agent_probe.run,
        "egress": offline_probe.run_egress,
        "tls": tls_probe.run,
    }[args.name]
    return _finish_probe(runner(target), args)


def _cmd_manifest(args) -> int:
    data = restore_probe.manifest(args.directory)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    print(f"wrote {args.output}: {len(data['files'])} files")
    return EXIT_OK


def _cmd_log(args) -> int:
    outcome = auditlog.verify(args.file, args.expected_head)
    if outcome.ok:
        print(f"ok: {outcome.entries} entries, head {outcome.head}")
        return EXIT_OK
    print(f"FAILED after {outcome.entries} good entries: {outcome.error}")
    return EXIT_FINDINGS


def _cmd_scan(args) -> int:
    text = sys.stdin.read() if args.file == "-" else open(args.file, "r", encoding="utf-8").read()
    if args.care_claims:
        claims = nevada.scan_claims(text)
        hits = [c for c in claims if c.kind != "disclaimer"]
        print(f"care claims: {len(hits)} to review, {len(claims) - len(hits)} disclaimer(s)")
        for c in hits:
            print(f"  [{c.kind}] {c.sentence[:200]}")
        print("A phrase scan for Nevada AB 406 sec. 7(1). A hit needs a person to read it; no hit is not a legal clearance.")
        return EXIT_FINDINGS if hits else EXIT_OK
    if args.hidden:
        concealed = hidden.scan(text)
        kinds = {}
        for c in concealed:
            kinds[c.kind] = kinds.get(c.kind, 0) + 1
        print("concealed text: " + (", ".join(f"{k} x{n}" for k, n in sorted(kinds.items())) if kinds else "none found"))
        for c in concealed:
            if c.revealed:
                print(f"  {c.kind} hides: {c.revealed[:200]}")
        return EXIT_FINDINGS if concealed else EXIT_OK
    findings = phi.scan(text)
    if args.redact:
        sys.stdout.write(phi.redact(text))
    else:
        kinds = {}
        for f in findings:
            kinds[f.kind] = kinds.get(f.kind, 0) + 1
        print("likely PHI: " + (", ".join(f"{k} x{n}" for k, n in sorted(kinds.items())) if kinds else "none found"))
    return EXIT_FINDINGS if findings else EXIT_OK


def _cmd_report(args) -> int:
    prof = profile_mod.load(args.profile)
    data = assess.load(args.assessment)
    if args.json:
        text = json.dumps(assess.summarize(data, prof), indent=2) + "\n"
    elif args.executive:
        text = buyer.executive_summary(data, prof)
    elif args.html:
        text = html.render(data, prof, bayes.load_model(args.model))
    else:
        text = report.render(data, prof)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {args.output}")
    else:
        sys.stdout.write(text)
    if args.strict and not assess.summarize(data, prof)["conformant"]:
        return EXIT_FINDINGS
    return EXIT_OK


def _cmd_belief(args) -> int:
    prof = profile_mod.load(args.profile)
    data = assess.load(args.assessment)
    model = bayes.load_model(args.model)
    if args.json:
        rows = bayes.beliefs(data, prof, model)
        print(json.dumps({"controls": rows, "summary": bayes.readiness(rows)}, indent=2))
    else:
        sys.stdout.write(bayes.render_text(data, prof, model))
    return EXIT_OK


def _cmd_next(args) -> int:
    prof = profile_mod.load(args.profile)
    data = assess.load(args.assessment)
    actions = bayes.next_actions(data, prof, bayes.load_model(args.model), top=args.top)
    if args.json:
        print(json.dumps(actions, indent=2))
        return EXIT_OK
    if not actions:
        print("nothing left that would change the picture")
        return EXIT_OK
    print("most uncertainty removed per unit of effort:")
    for a in actions:
        print(f"  {a['control']:<8} {a['action']:<38} {a['bits']:.2f} bits  cost {a['cost']}")
    return EXIT_OK


def _cmd_predict(args) -> int:
    prof = profile_mod.load(args.profile)
    data = assess.load(args.assessment)
    model_p = bayes.predicted_clean(data, prof, bayes.load_model(args.model), args.probe)
    assess.predict(data, args.probe, args.probability, args.by, model_p)
    assess.save(data, args.assessment)
    print(f"recorded: {args.by} gives the {args.probe} probe a {args.probability * 100:.0f}% chance of coming back clean")
    print(f"the model gives it {model_p * 100:.0f}%. The next run that tests something settles both.")
    return EXIT_OK


def _cmd_calibration(args) -> int:
    if args.pool:
        import glob
        import os

        docs = []
        for path in sorted(glob.glob(os.path.join(args.pool, "*.json"))):
            with open(path, "r", encoding="utf-8") as fh:
                docs.append(json.load(fh))
        pooled = bayes.pooled_calibration(docs)
        if args.json:
            print(json.dumps(pooled, indent=2))
            return EXIT_OK
        print(f"{pooled['settled']} settled predictions from {pooled['files']} contributed file(s)")
        for r in pooled["probes"]:
            model = f"{r['brier_model']:.3f}" if r["brier_model"] is not None else "  n/a"
            print(f"  {r['probe']:<10} {r['settled']:>4} settled  came back clean {r['clean_rate'] * 100:3.0f}%  "
                  f"Brier: people {r['brier_people']:.3f}, belief.yaml {model}")
        if pooled["settled"] < 100:
            print("  Fewer than 100 settled predictions. Too few to change the numbers in belief.yaml; keep contributing.")
        return EXIT_OK
    data = assess.load(args.assessment)
    if args.export:
        exported = bayes.export_calibration(data)
        with open(args.export, "w", encoding="utf-8") as fh:
            json.dump(exported, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"wrote {args.export}: {len(exported['records'])} settled prediction(s), no names, no product, months only")
        print("Read it before you share it. To contribute it, see calibration-data/README.md.")
        return EXIT_OK
    rows = bayes.calibration(data)
    still_open = sum(1 for q in data.get("predictions") or [] if q["outcome"] is None)
    if args.json:
        print(json.dumps({"forecasters": rows, "open": still_open}, indent=2))
        return EXIT_OK
    if not rows:
        print(f"no settled predictions yet ({still_open} open). Use `pz predict` before you run a probe.")
        return EXIT_OK
    print("Brier score (0 is perfect, 0.25 is a coin flip, lower is better):")
    for r in rows:
        print(f"  {r['forecaster']:<28} {r['brier']:.3f}  over {r['settled']} settled")
    if max(r["settled"] for r in rows) < 20:
        print("  Fewer than 20 settled predictions. Differences this size are noise; keep predicting.")
    print("  These scores are for forecasters to learn from. They grade guesses about a system, not anyone's work;")
    print("  do not use them to rate staff. Use a role or an alias with --by if that is a risk on your team.")
    return EXIT_OK


def _cmd_build(args) -> int:
    data = assess.load(args.assessment)
    previous = data.get("build")
    data["build"] = args.id
    assess.save(data, args.assessment)
    print(f"current build set to {args.id}" + (f" (was {previous}); evidence from other builds now counts for less" if previous else ""))
    return EXIT_OK


def _cmd_replay(args) -> int:
    reproduced, differences = replay_mod.replay(args.evidence)
    return _report_errors(differences, "REPRODUCED: the recorded exchanges yield exactly the findings in this file")


def _cmd_fragile(args) -> int:
    prof = profile_mod.load(args.profile)
    data = assess.load(args.assessment)
    rows = bayes.fragility(data, prof, bayes.load_model(args.model))
    if args.json:
        print(json.dumps(rows, indent=2))
        return EXIT_OK
    if not rows:
        print("no supporting evidence recorded yet")
        return EXIT_OK
    print("if everything one source told you were wrong:")
    for r in rows:
        print(f"  {r['source']:<34} props up {len(r['controls']):>2} control(s), {r['belief_lost']:.1f} more expected broken")
    return EXIT_OK


def _cmd_keygen(args) -> int:
    public = seal_mod.keygen(args.output)
    print(f"private seed written to {args.output} (keep it out of the repo)")
    from .custody import backend

    if backend() == "pure-python":
        print('signing will use the built-in pure-Python code, which is not constant-time. `pip install "patient-zero[sign]"` '
              "switches to OpenSSL.")
    print(f"public key: {public}")
    return EXIT_OK


def _cmd_seal(args) -> int:
    document = seal_mod.seal(args.assessment, args.key, args.output, signer_name=args.signer or "", domain=args.domain)
    head = document["head"]
    print(f"sealed {head['item_count']} files  root {head['merkle_root']}")
    print(f"signed by {head['signer']['public_key']}" + (f"  follows {head['previous_root'][:16]}..." if head["previous_root"] else ""))
    if head["signer"].get("domain"):
        print(f"claims {head['signer']['domain']}: publish the key there with `pz identity`, or the claim cannot be checked")
    else:
        print("no --domain given: this key proves the same key signed each seal, not who holds it")
    print(f"wrote {args.output}")
    return EXIT_OK


def _print_description(document) -> None:
    info = seal_mod.describe(document)
    signer = info["signer"]
    print(f"  {info['product']}  level {info['level']}  profile {info['profile_version']}")
    print(f"  sealed {seal_mod.age_phrase(info['age_days'])} ({info['sealed_at']}) by {signer.get('name') or 'an unnamed signer'}"
          + (f", claiming {signer['domain']}" if signer.get("domain") else ""))
    summary = info["summary"]
    if summary:
        print(f"  {summary['confirmed']} of {summary['controls']} safeguards confirmed by a person "
              f"({summary['confirmed_by_independent']} by someone independent), {summary['tested_clean_only']} tested clean only, "
              f"{summary['failed']} failing, {summary['not_assessed']} not assessed"
              + (f"; build {summary['build']}" if summary.get("build") else ""))
    for c in info["cosigners"]:
        print(f"  co-signed by {c['name']} as {c['role']}" + (f", claiming {c['domain']}" if c.get("domain") else "")
              + (f": \"{c['statement']}\"" if c.get("statement") else ""))
    if info["age_days"] is not None and info["age_days"] > 365:
        print("  NOTE: this seal is more than a year old. Ask for a current one.")


def _cmd_cosign(args) -> int:
    errors = seal_mod.verify_seal(args.seal)
    if errors:
        return _report_errors(errors, "")
    body = seal_mod.cosign(args.seal, args.key, args.name, args.role, args.statement or "", args.domain)
    print(f"co-signed as {body['role']} with {body['signer']['public_key']}")
    print(f"updated {args.seal}. The original signature and every sealed file are unchanged.")
    return EXIT_OK


def _cmd_identity(args) -> int:
    keys = list(args.public_key or [])
    if args.key:
        keys.append(seal_mod.generate_keypair(bytes.fromhex(seal_mod._read_key(args.key)))[1])
    if not keys:
        print("pz identity needs --key or --public-key", file=sys.stderr)
        return EXIT_USAGE
    document = seal_mod.identity_document(args.domain, keys, args.retired)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"wrote {args.output}. Publish it at https://{document['domain']}{seal_mod.IDENTITY_PATH}")
    print("Anyone can then run `pz verify --check-domain` to confirm the key that signed your seals is yours.")
    return EXIT_OK


def _cmd_bundle(args) -> int:
    packed = seal_mod.bundle(args.seal, args.output)
    print(f"wrote {args.output}: the seal and {len(packed['files'])} files in one file")
    print("Send it to a buyer. They can check it with `pz verify <file>` or by dropping it on docs/verify/index.html in a browser.")
    return EXIT_OK


def _cmd_badge(args) -> int:
    with open(args.seal, "r", encoding="utf-8") as fh:
        document = json.load(fh)
    document = document.get("seal", document)
    errors = seal_mod._check_head(document, None)
    if errors:
        return _report_errors(errors, "")
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(badge_mod.svg(document))
    print(f"wrote {args.output}: {badge_mod.message(document)}")
    print("\nPaste this where you show the badge. The badge must link to the sealed evidence (see TRADEMARK.md):\n")
    print(badge_mod.markdown(document, args.report_url, args.output))
    return EXIT_OK


def _cmd_mcp(args) -> int:
    from . import mcp

    return mcp.serve()


def _cmd_conformance(args) -> int:
    from . import conformance

    failures = conformance.run(args.vectors)
    return _report_errors(failures, f"CONFORMS: every vector in {args.vectors or 'the bundled set'} reproduced")


def _report_errors(errors, ok_message) -> int:
    if errors:
        for e in errors:
            print(f"FAILED: {e}")
        return EXIT_FINDINGS
    print(ok_message)
    return EXIT_OK


def _cmd_verify(args) -> int:
    with open(args.seal, "r", encoding="utf-8") as fh:
        document = json.load(fh)
    if isinstance(document, dict) and document.get("schema") == seal_mod.BUNDLE_SCHEMA:
        errors, document = seal_mod.verify_bundle(args.seal, expect_public_key=args.public_key)
    else:
        errors = seal_mod.verify_seal(args.seal, expect_public_key=args.public_key)
    if not errors and args.check_domain:
        errors = seal_mod.check_domains(document)
    code = _report_errors(errors, "VERIFIED: signature valid, Merkle root matches, every file unchanged"
                          + (", and each signer's domain lists their key" if args.check_domain else ""))
    if not errors:
        _print_description(document)
        print("  This shows the files are what was signed. It does not show the claims in them are true.")
    return code


def _cmd_prove(args) -> int:
    proof = seal_mod.prove(args.seal, args.file)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(proof, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"wrote {args.output}: proves {args.file} is one of {proof['head']['item_count']} sealed files, reveals no others")
    return EXIT_OK


def _cmd_verify_proof(args) -> int:
    with open(args.proof, "r", encoding="utf-8") as fh:
        proof = json.load(fh)
    errors = seal_mod.verify_proof(proof, args.file, expect_public_key=args.public_key)
    return _report_errors(errors, "VERIFIED: this file is part of the signed assessment")


def _cmd_check(args) -> int:
    result = check_mod.run(args.path, register=args.register, include_tests=args.include_tests, exclude=args.exclude or [])
    if args.sarif:
        text = json.dumps(check_mod.to_sarif(result), indent=2) + "\n"
    elif args.json:
        text = json.dumps(result.to_dict(), indent=2) + "\n"
    else:
        text = check_mod.render_text(result, top=args.top)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {args.output}: {len(result.issues)} finding(s) in {result.files} files")
    else:
        sys.stdout.write(text)
    if result.void:
        return EXIT_USAGE
    return EXIT_FINDINGS if result.failed(args.fail_on) else EXIT_OK


def _write_or_print(text: str, output: Optional[str], note: str = "") -> None:
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {output}" + (f": {note}" if note else ""))
    else:
        sys.stdout.write(text)


def _cmd_synth(args) -> int:
    from . import synth

    data = synth.generate(args.patients, args.seed, args.tenants)
    markers = ", ".join(f"{t['tenant']}={t['canary']}" for t in data["tenants"])
    _write_or_print(synth.to_csv(data) if args.csv else synth.to_json(data), args.output,
                    f"{args.patients} made-up patients; test markers {markers}")
    return EXIT_OK


def _cmd_pilot(args) -> int:
    from . import pilot

    if args.pilot_command == "init":
        written = pilot.init(args.folder, args.product, args.level, args.base_url, args.patients)
        print(f"wrote {args.folder}/: {', '.join(written)}")
        print("Start with PILOT.md. Nothing can be tested until rules-of-engagement.md is signed and target.yaml says authorized: true.")
        return EXIT_OK
    outcome = pilot.run(args.folder, args.path)
    for r in outcome["ran"]:
        print(f"{r['probe']}: {r['checks']} checks, " + ("VOID" if r["void"] else f"{len(r['findings'])} kind(s) of finding"))
    for s in outcome["skipped"]:
        print(f"skipped {s}")
    print(f"report: {outcome['report']}")
    return EXIT_FINDINGS if outcome["failed"] else EXIT_OK


def _cmd_vendors(args) -> int:
    from . import fleet

    rows = fleet.read(args.folder)
    if not rows:
        print(f"no patient-zero bundles in {args.folder}. A vendor makes one with `pz bundle`.", file=sys.stderr)
        return EXIT_USAGE
    if args.json:
        for row in rows:
            row.pop("statuses", None)
        text = json.dumps({"reports": rows, "cohort": fleet.cohort(fleet.read(args.folder))}, indent=2) + "\n"
    else:
        text = fleet.render(rows, anonymize=args.anonymize)
    _write_or_print(text, args.output)
    return EXIT_FINDINGS if any(not r["verified"] for r in rows) else EXIT_OK


def _cmd_sandbox(args) -> int:
    from . import sandbox

    result = sandbox.evaluate(args.folder, args.path)
    sys.stdout.write(json.dumps(result, indent=2) + "\n" if args.json else sandbox.render(result))
    return EXIT_OK if result["entry_met"] else EXIT_FINDINGS


def _cmd_brief(args) -> int:
    from . import brief

    sys.stdout.write(brief.render(args.audience, args.overlay))
    return EXIT_OK


def _cmd_demo(args) -> int:
    if args.serve:
        from .demo.leaky_clinic import serve

        serve(args.port, vulnerable=not args.patched)
        return EXIT_OK
    from .demo.run import run, run_brief

    return run_brief() if args.brief else run()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pz", description="Open PHI safeguard profile for AI applications.")
    parser.add_argument("--version", action="version", version=f"patient-zero {__version__}")
    parser.add_argument("--profile", help="path to an alternate controls.yaml")
    parser.add_argument("--model", help="path to an alternate belief.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("check", help="read a project folder and list the mistakes to fix first, in plain language")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--register", help="subprocessor register (default: register.yaml found in the project)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 for GitHub code scanning and editors")
    p.add_argument("-o", "--output")
    p.add_argument("--top", type=int, default=3, help="how many to show as 'fix first'")
    p.add_argument("--fail-on", choices=check_mod.SEVERITIES, default="medium", help="exit 1 at this severity or worse")
    p.add_argument("--include-tests", action="store_true", help="also read test and fixture folders")
    p.add_argument("--exclude", action="append", help="glob of paths to skip, repeatable")
    p.set_defaults(func=_cmd_check)

    p = sub.add_parser("controls", help="list the controls")
    p.add_argument("--level", choices=profile_mod.LEVELS)
    p.add_argument("--family")
    p.add_argument("--json", action="store_true")
    p.add_argument("--validate", action="store_true", help="check the catalogue and exit")
    p.add_argument("--markdown", action="store_true", help="the whole profile as a document")
    p.set_defaults(func=_cmd_controls)

    p = sub.add_parser("coverage", help="which controls have a probe, reference code, or neither")
    p.add_argument("--markdown", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=_cmd_coverage)

    p = sub.add_parser("questionnaire", help="plain-language questions for a buyer to send an AI vendor")
    p.add_argument("--level", choices=profile_mod.LEVELS, default="L1")
    p.add_argument("--overlay", choices=buyer.overlays(), help="add a state's requirements")
    p.set_defaults(func=_cmd_questionnaire)

    p = sub.add_parser("overlay", help="state requirements on top of HIPAA")
    p.add_argument("name", choices=buyer.overlays())
    p.add_argument("--markdown", action="store_true")
    p.add_argument("--review", action="store_true", help="a form for a lawyer in that state to mark up")
    p.set_defaults(func=_cmd_overlay)

    p = sub.add_parser("synth", help="made-up patient records for a pilot, obviously fake, with a test marker per clinic")
    p.add_argument("--patients", type=int, default=25)
    p.add_argument("--tenants", type=int, default=2, help="how many test clinics to split them across")
    p.add_argument("--seed", type=int, default=1, help="same seed, same records")
    p.add_argument("--csv", action="store_true")
    p.add_argument("-o", "--output")
    p.set_defaults(func=_cmd_synth)

    p = sub.add_parser("pilot", help="everything one real pilot needs: permission form, test data, target file, run sheet")
    pilotsub = p.add_subparsers(dest="pilot_command", required=True)
    v = pilotsub.add_parser("init", help="write the pilot folder")
    v.add_argument("folder")
    v.add_argument("--product", required=True)
    v.add_argument("--level", choices=profile_mod.LEVELS, default="L1")
    v.add_argument("--base-url", default="https://staging.example.com", help="the test system, never production")
    v.add_argument("--patients", type=int, default=20)
    v.set_defaults(func=_cmd_pilot)
    v = pilotsub.add_parser("run", help="run every probe the target configures and write pilot-report.md")
    v.add_argument("folder", nargs="?", default=".")
    v.add_argument("--path", help="also check the product's source folder")
    v.set_defaults(func=_cmd_pilot)

    p = sub.add_parser("vendors", help="read a folder of sealed bundles: which are current, verified, co-signed, failing")
    p.add_argument("folder")
    p.add_argument("--anonymize", action="store_true", help="Product A, Product B: for a cohort that will not rank its members")
    p.add_argument("--json", action="store_true")
    p.add_argument("-o", "--output")
    p.set_defaults(func=_cmd_vendors)

    p = sub.add_parser("sandbox", help="which entry and exit criteria of a healthcare AI sandbox a pilot meets")
    p.add_argument("folder", nargs="?", default=".")
    p.add_argument("--path", help="the product's source folder, for the code criteria")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=_cmd_sandbox)

    p = sub.add_parser("brief", help="a one-page brief for people who do not build software")
    p.add_argument("audience", choices=["legislator", "judge"])
    p.add_argument("--overlay", choices=buyer.overlays(), help="show what that state's rules say beside each question")
    p.set_defaults(func=_cmd_brief)

    p = sub.add_parser("init", help="start an assessment file")
    p.add_argument("--product", required=True)
    p.add_argument("--level", required=True, choices=profile_mod.LEVELS)
    p.add_argument("-o", "--output", default="assessment.yaml")
    p.set_defaults(func=_cmd_init)

    p = sub.add_parser("set", help="record an assessor's judgment on one control")
    p.add_argument("control")
    p.add_argument("status", choices=assess.STATUSES)
    p.add_argument("--note")
    p.add_argument("--evidence", action="append")
    p.add_argument("--assessor", default="assessor")
    p.add_argument("--independent", action="store_true", help="the assessor is independent of the team that built the control")
    p.add_argument("-a", "--assessment", default="assessment.yaml")
    p.set_defaults(func=_cmd_set)

    p = sub.add_parser("probe", help="run a probe and write evidence")
    p.add_argument("name", choices=PROBES)
    p.add_argument("--config", help="target.yaml (network probes and egress)")
    p.add_argument("--manifest", help="checksum manifest from `pz manifest` (restore probe)")
    p.add_argument("--file", help="audit log file (log and claims probes)")
    p.add_argument("--transcript", help="agent transcript, JSON Lines (claims probe)")
    p.add_argument("--path", default=".", help="directory or file (stack, rls and restore probes)")
    p.add_argument("--expected-head", help="anchored head hash (log probe)")
    p.add_argument("-a", "--assessment", help="assessment file to update")
    p.add_argument("--evidence-dir", default="evidence")
    p.set_defaults(func=_cmd_probe)

    p = sub.add_parser("manifest", help="checksum every file under a directory, for the restore probe")
    p.add_argument("directory")
    p.add_argument("-o", "--output", default="manifest.json")
    p.set_defaults(func=_cmd_manifest)

    p = sub.add_parser("log", help="audit log tools")
    logsub = p.add_subparsers(dest="log_command", required=True)
    v = logsub.add_parser("verify", help="verify a hash-chained log")
    v.add_argument("file")
    v.add_argument("--expected-head")
    v.set_defaults(func=_cmd_log)

    p = sub.add_parser("scan", help="flag likely PHI in text (heuristic)")
    p.add_argument("file", help="file to scan, or - for stdin")
    p.add_argument("--redact", action="store_true", help="print the text with findings masked")
    p.add_argument("--care-claims", action="store_true",
                   help="look for wording that presents an AI as a therapist or as mental health care (Nevada AB 406)")
    p.add_argument("--hidden", action="store_true", help="look for concealed text instead: invisible characters, hidden markup, comments")
    p.set_defaults(func=_cmd_scan)

    p = sub.add_parser("report", help="render the assessment")
    p.add_argument("assessment", nargs="?", default="assessment.yaml")
    p.add_argument("-o", "--output")
    p.add_argument("--json", action="store_true", help="summary as JSON")
    p.add_argument("--html", action="store_true", help="self-contained HTML with belief per control")
    p.add_argument("--executive", action="store_true", help="one page in plain language for a decision maker")
    p.add_argument("--strict", action="store_true", help="exit 1 unless conformant")
    p.set_defaults(func=_cmd_report)

    p = sub.add_parser("belief", help="P(control holds) for every control, given the evidence so far")
    p.add_argument("assessment", nargs="?", default="assessment.yaml")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=_cmd_belief)

    p = sub.add_parser("next", help="rank the evidence worth gathering next")
    p.add_argument("assessment", nargs="?", default="assessment.yaml")
    p.add_argument("--top", type=int, default=10)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=_cmd_next)

    p = sub.add_parser("predict", help="before a probe runs, record how likely you think it is to come back clean")
    p.add_argument("probe", choices=PROBES)
    p.add_argument("probability", type=float, help="0 to 1")
    p.add_argument("--by", required=True, help="who is predicting (a name, role or alias; scores are not for rating staff)")
    p.add_argument("-a", "--assessment", default="assessment.yaml")
    p.set_defaults(func=_cmd_predict)

    p = sub.add_parser("calibration", help="score past predictions, yours and the model's")
    p.add_argument("assessment", nargs="?", default="assessment.yaml")
    p.add_argument("--json", action="store_true")
    p.add_argument("--export", metavar="FILE", help="write settled predictions with names and product removed, for pooling")
    p.add_argument("--pool", metavar="DIR", help="score every contributed file in a directory, such as calibration-data/")
    p.set_defaults(func=_cmd_calibration)

    p = sub.add_parser("build", help="set the release under assessment; older evidence then counts for less")
    p.add_argument("id")
    p.add_argument("-a", "--assessment", default="assessment.yaml")
    p.set_defaults(func=_cmd_build)

    p = sub.add_parser("replay", help="re-derive a probe's findings from its recorded exchanges, offline")
    p.add_argument("evidence")
    p.set_defaults(func=_cmd_replay)

    p = sub.add_parser("fragile", help="which single source of evidence the picture leans on most")
    p.add_argument("assessment", nargs="?", default="assessment.yaml")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=_cmd_fragile)

    p = sub.add_parser("keygen", help="create an Ed25519 signing key")
    p.add_argument("-o", "--output", default="pz.key")
    p.set_defaults(func=_cmd_keygen)

    p = sub.add_parser("seal", help="sign a Merkle root over the assessment and its evidence")
    p.add_argument("assessment", nargs="?", default="assessment.yaml")
    p.add_argument("--key", default="pz.key")
    p.add_argument("--signer", help="name to record beside the public key")
    p.add_argument("--domain", help="a domain you control, where you publish the key with `pz identity`")
    p.add_argument("-o", "--output", default="seal.json")
    p.set_defaults(func=_cmd_seal)

    p = sub.add_parser("cosign", help="add a second party's signature to a seal: an assessor, a customer, counsel")
    p.add_argument("seal", nargs="?", default="seal.json")
    p.add_argument("--key", required=True, help="the co-signer's own key, not the one that sealed")
    p.add_argument("--name", required=True)
    p.add_argument("--role", required=True, choices=seal_mod.ROLES)
    p.add_argument("--statement", help="what the co-signer is saying, in their own words")
    p.add_argument("--domain", help="a domain the co-signer controls")
    p.set_defaults(func=_cmd_cosign)

    p = sub.add_parser("identity", help="write the file that ties your signing key to your domain")
    p.add_argument("--domain", required=True)
    p.add_argument("--key", help="private key file; only its public half is written")
    p.add_argument("--public-key", action="append", help="an active public key, repeatable")
    p.add_argument("--retired", action="append", help="a public key no longer in use, repeatable")
    p.add_argument("-o", "--output", default="patient-zero.json")
    p.set_defaults(func=_cmd_identity)

    p = sub.add_parser("bundle", help="pack a seal and its files into one file a buyer can verify in a browser")
    p.add_argument("seal", nargs="?", default="seal.json")
    p.add_argument("-o", "--output", default="patient-zero-bundle.json")
    p.set_defaults(func=_cmd_bundle)

    p = sub.add_parser("badge", help="a badge that states what a seal says and links to the evidence")
    p.add_argument("seal", nargs="?", default="seal.json", help="seal.json or a bundle")
    p.add_argument("--report-url", required=True, help="where the sealed evidence can be downloaded and verified")
    p.add_argument("-o", "--output", default="patient-zero-badge.svg")
    p.set_defaults(func=_cmd_badge)

    p = sub.add_parser("mcp", help="serve patient-zero's read-only tools to a coding agent over stdio (Model Context Protocol)")
    p.set_defaults(func=_cmd_mcp)

    p = sub.add_parser("conformance", help="run the spec's test vectors against this implementation")
    p.add_argument("vectors", nargs="?", help="directory of vector files (default: the bundled set)")
    p.set_defaults(func=_cmd_conformance)

    p = sub.add_parser("verify", help="verify a seal and every file under it")
    p.add_argument("seal", nargs="?", default="seal.json", help="seal.json or a one-file bundle")
    p.add_argument("--public-key", help="require this signer")
    p.add_argument("--check-domain", action="store_true",
                   help="also fetch https://<domain>/.well-known/patient-zero.json for each signer (opens a network connection)")
    p.set_defaults(func=_cmd_verify)

    p = sub.add_parser("prove", help="prove one evidence file belongs to a seal without revealing the rest")
    p.add_argument("file")
    p.add_argument("--seal", default="seal.json")
    p.add_argument("-o", "--output", default="proof.json")
    p.set_defaults(func=_cmd_prove)

    p = sub.add_parser("verify-proof", help="check a single-file proof")
    p.add_argument("proof")
    p.add_argument("file")
    p.add_argument("--public-key", help="require this signer")
    p.set_defaults(func=_cmd_verify_proof)

    p = sub.add_parser("demo", help="investigate the bundled Leaky Clinic app, offline")
    p.add_argument("--brief", action="store_true", help="the short version in plain language")
    p.add_argument("--serve", action="store_true", help="just run the demo app so you can probe it yourself")
    p.add_argument("--patched", action="store_true", help="with --serve, run the patched build")
    p.add_argument("--port", type=int, default=8099)
    p.set_defaults(func=_cmd_demo)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ProbeRefused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except (FileExistsError, FileNotFoundError, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
