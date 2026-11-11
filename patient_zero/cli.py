"""pz: the patient-zero command line."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __version__, assess, auditlog, bayes, html, phi, profile as profile_mod, report
from .probes import ProbeRefused, load_target, write_evidence
from .probes import agent as agent_probe
from .probes import isolation as isolation_probe
from .probes import offline as offline_probe
from .probes import tls as tls_probe

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2


def _cmd_controls(args) -> int:
    prof = profile_mod.load(args.profile)
    if args.validate:
        print(f"profile {prof.version}: {len(prof.controls)} controls in {len(prof.families)} families, valid")
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


def _cmd_log(args) -> int:
    outcome = auditlog.verify(args.file, args.expected_head)
    if outcome.ok:
        print(f"ok: {outcome.entries} entries, head {outcome.head}")
        return EXIT_OK
    print(f"FAILED after {outcome.entries} good entries: {outcome.error}")
    return EXIT_FINDINGS


def _cmd_scan(args) -> int:
    text = sys.stdin.read() if args.file == "-" else open(args.file, "r", encoding="utf-8").read()
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


def _cmd_demo(args) -> int:
    if args.serve:
        from .demo.leaky_clinic import serve

        serve(args.port, vulnerable=not args.patched)
        return EXIT_OK
    from .demo.run import run

    return run()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pz", description="Open PHI safeguard profile for AI applications.")
    parser.add_argument("--version", action="version", version=f"patient-zero {__version__}")
    parser.add_argument("--profile", help="path to an alternate controls.yaml")
    parser.add_argument("--model", help="path to an alternate belief.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("controls", help="list the controls")
    p.add_argument("--level", choices=profile_mod.LEVELS)
    p.add_argument("--family")
    p.add_argument("--json", action="store_true")
    p.add_argument("--validate", action="store_true", help="check the catalogue and exit")
    p.set_defaults(func=_cmd_controls)

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
    p.add_argument("name", choices=["isolation", "agent", "egress", "tls", "log"])
    p.add_argument("--config", help="target.yaml (not needed for log)")
    p.add_argument("--file", help="audit log file (log probe)")
    p.add_argument("--expected-head", help="anchored head hash (log probe)")
    p.add_argument("-a", "--assessment", help="assessment file to update")
    p.add_argument("--evidence-dir", default="evidence")
    p.set_defaults(func=_cmd_probe)

    p = sub.add_parser("log", help="audit log tools")
    logsub = p.add_subparsers(dest="log_command", required=True)
    v = logsub.add_parser("verify", help="verify a hash-chained log")
    v.add_argument("file")
    v.add_argument("--expected-head")
    v.set_defaults(func=_cmd_log)

    p = sub.add_parser("scan", help="flag likely PHI in text (heuristic)")
    p.add_argument("file", help="file to scan, or - for stdin")
    p.add_argument("--redact", action="store_true", help="print the text with findings masked")
    p.set_defaults(func=_cmd_scan)

    p = sub.add_parser("report", help="render the assessment")
    p.add_argument("assessment", nargs="?", default="assessment.yaml")
    p.add_argument("-o", "--output")
    p.add_argument("--json", action="store_true", help="summary as JSON")
    p.add_argument("--html", action="store_true", help="self-contained HTML with belief per control")
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

    p = sub.add_parser("demo", help="investigate the bundled Leaky Clinic app, offline")
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
    except (FileNotFoundError, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
