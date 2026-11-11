import json
import os

import pytest
import yaml

from patient_zero import assess, bayes, profile, seal
from patient_zero.auditlog import AuditLog
from patient_zero.cli import main
from patient_zero.custody import MerkleTree, generate_keypair, sign, verify, verify_inclusion_proof
from patient_zero.demo.leaky_clinic import CANARY, target_for
from patient_zero.probes import ProbeRefused, claims, isolation, stack

PROF = profile.load()
MODEL = bayes.load_model()


# --- primitives ---------------------------------------------------------------

def test_ed25519_rfc8032_vectors():
    private, public = generate_keypair(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
    assert public == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    signature = sign(b"", private)
    assert signature == ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
                         "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    assert verify(b"", signature, public) and not verify(b"altered", signature, public)
    # RFC 8032 section 7.1, test 2 (one-byte message)
    private, public = generate_keypair(bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"))
    assert public == "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    assert sign(bytes.fromhex("72"), private) == (
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")


def test_ed25519_rejects_garbage():
    _, public = generate_keypair()
    assert not verify(b"x", "00" * 64, public)
    assert not verify(b"x", "zz", public)
    assert not verify(b"x", "00" * 64, "00" * 32)


@pytest.mark.parametrize("n", [1, 2, 3, 7, 8])
def test_merkle_inclusion_for_every_leaf(n):
    leaves = [f"leaf-{i}".encode() for i in range(n)]
    tree = MerkleTree(leaves)
    for i, leaf in enumerate(leaves):
        proof = tree.inclusion_proof(i)
        assert verify_inclusion_proof(leaf, tree.root_hex, proof)
        assert not verify_inclusion_proof(b"other", tree.root_hex, proof)
    assert MerkleTree(leaves + [b"extra"]).root_hex != tree.root_hex


# --- seal ---------------------------------------------------------------------

@pytest.fixture
def sealed(tmp_path):
    os.makedirs(tmp_path / "evidence")
    for name in ("a.json", "b.json", "c.json"):
        (tmp_path / "evidence" / name).write_text(json.dumps({"file": name}))
    data = assess.new("demo", "L0", PROF)
    assess.set_status(data, "GATE-1", "pass", evidence=["evidence/a.json"])
    assess.set_status(data, "GATE-2", "pass", evidence=["evidence/b.json", "evidence/c.json"])
    a = str(tmp_path / "assessment.yaml")
    assess.save(data, a)
    key = str(tmp_path / "pz.key")
    public = seal.keygen(key)
    out = str(tmp_path / "seal.json")
    document = seal.seal(a, key, out, signer_name="jv")
    return tmp_path, a, key, out, public, document


def test_seal_verifies_and_key_file_is_private(sealed):
    tmp, a, key, out, public, document = sealed
    assert document["head"]["item_count"] == 4 and document["head"]["signer"]["public_key"] == public
    assert seal.verify_seal(out) == []
    assert seal.verify_seal(out, expect_public_key=public) == []
    assert oct(os.stat(key).st_mode & 0o777) == "0o600"
    with pytest.raises(FileExistsError):
        seal.keygen(key)  # never overwrite a key
    assert open(key).read().strip() not in open(out).read()


def test_seal_detects_every_kind_of_tampering(sealed):
    tmp, a, key, out, public, document = sealed
    (tmp / "evidence" / "b.json").write_text('{"file": "B.json"}')
    assert seal.verify_seal(out) == ["changed since sealing: evidence/b.json"]
    os.remove(tmp / "evidence" / "c.json")
    assert "missing: evidence/c.json" in seal.verify_seal(out)

    doc = json.load(open(out))
    doc["head"]["level"] = "L2"  # claim a higher level than was sealed
    json.dump(doc, open(out, "w"))
    assert "signature does not verify" in seal.verify_seal(out)

    doc = json.loads(json.dumps(document))
    doc["items"] = doc["items"][:-1]  # quietly drop an item
    json.dump(doc, open(out, "w"))
    errors = seal.verify_seal(out)
    assert "item count does not match the signed head" in errors
    assert "item list does not match the signed Merkle root" in errors

    json.dump(document, open(out, "w"))
    _, other = generate_keypair()
    assert "signed by a different key than expected" in seal.verify_seal(out, expect_public_key=other)


def test_resealing_chains_to_the_previous_root(sealed):
    tmp, a, key, out, public, document = sealed
    again = seal.seal(a, key, out)
    assert again["head"]["previous_root"] == document["head"]["merkle_root"]


def test_seal_refuses_missing_or_outside_evidence(sealed, tmp_path):
    tmp, a, key, out, *_ = sealed
    data = assess.load(a)
    data["controls"]["GATE-3"]["evidence"] = ["evidence/nope.json"]
    assess.save(data, a)
    with pytest.raises(FileNotFoundError):
        seal.seal(a, key, out)
    data["controls"]["GATE-3"]["evidence"] = ["../../etc/hostname"]
    assess.save(data, a)
    with pytest.raises(ValueError):
        seal.seal(a, key, out)


def test_single_file_proof_reveals_nothing_else(sealed):
    tmp, a, key, out, public, _ = sealed
    proof = seal.prove(out, "evidence/b.json")
    text = json.dumps(proof)
    assert "a.json" not in text and "c.json" not in text and "assessment.yaml" not in text
    assert seal.verify_proof(proof, str(tmp / "evidence" / "b.json"), expect_public_key=public) == []
    assert "file does not match the proven item" in seal.verify_proof(proof, str(tmp / "evidence" / "a.json"))
    forged = json.loads(text)
    forged["item"]["path"] = "evidence/other.json"
    assert "inclusion proof does not lead to the signed root" in seal.verify_proof(forged, str(tmp / "evidence" / "b.json"))
    with pytest.raises(KeyError):
        seal.prove(out, "evidence/zzz.json")


def test_cli_seal_roundtrip(sealed, tmp_path, capsys, monkeypatch):
    tmp, a, key, out, public, _ = sealed
    monkeypatch.chdir(tmp)
    assert main(["seal", "--key", "pz.key"]) == 0
    assert main(["verify"]) == 0
    assert main(["prove", "evidence/a.json", "-o", "p.json"]) == 0
    assert main(["verify-proof", "p.json", "evidence/a.json", "--public-key", public]) == 0
    assert main(["verify-proof", "p.json", "evidence/b.json"]) == 1
    (tmp / "assessment.yaml").write_text(open(a).read().replace("demo", "Demo"))
    capsys.readouterr()
    assert main(["verify"]) == 1
    assert "changed since sealing: assessment.yaml" in capsys.readouterr().out
    assert main(["keygen", "-o", "pz.key"]) == 2  # refuses to overwrite


# --- stack probe --------------------------------------------------------------

MESSY = {"services": {
    "ollama": {"image": "ollama/ollama:latest", "ports": ["11434:11434"], "environment": ["OLLAMA_ORIGINS=*"]},
    "ui": {"image": "ghcr.io/open-webui/open-webui", "ports": [{"published": 3000, "target": 8080}]},
    "vec": {"image": "qdrant/qdrant", "ports": ["0.0.0.0:6333:6333"]},
    "db": {"image": "postgres:16", "network_mode": "host"},
    "worker": {"image": "app", "privileged": True, "volumes": ["/var/run/docker.sock:/var/run/docker.sock"]},
}}
HARDENED = {"services": {
    "ollama": {"image": "ollama/ollama:0.12.3"},
    "ui": {"image": "ghcr.io/open-webui/open-webui", "ports": ["127.0.0.1:3000:8080"]},
    "vec": {"image": "qdrant/qdrant", "ports": [{"published": 6333, "target": 6333, "host_ip": "127.0.0.1"}]},
    "web": {"image": "nginx", "ports": ["443:443"]},
}}


def test_stack_probe_flags_exposure(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(yaml.safe_dump(MESSY))
    result = stack.run(str(tmp_path))
    titles = sorted(f.title for f in result.findings)
    assert titles == [
        "Docker socket mounted into a container",
        "data store on the host network",
        "inference API published to all interfaces",
        "model UI published to all interfaces",
        "privileged container",
        "vector database published to all interfaces",
        "wildcard CORS (OLLAMA_ORIGINS=*)",
    ]
    assert result.checks_for["GATE-3"] == 5


def test_stack_probe_passes_hardened_and_fails_closed(tmp_path):
    (tmp_path / "compose.yaml").write_text(yaml.safe_dump(HARDENED))
    assert stack.run(str(tmp_path)).clean
    (tmp_path / "compose.yaml").write_text("services: [not, a, mapping")
    with pytest.raises(ProbeRefused):
        stack.run(str(tmp_path))
    with pytest.raises(ProbeRefused):
        stack.run(str(tmp_path / "empty-dir-that-does-not-exist"))


@pytest.mark.parametrize("raw,expected", [
    ("8080", ("", 0)), ("8080:80", ("", 8080)), ("127.0.0.1:8080:80", ("127.0.0.1", 8080)),
    ("8080:80/tcp", ("", 8080)), ("[::1]:8080:80", ("[::1]", 8080)), ("9000-9005:9000-9005", ("", 9000)),
])
def test_port_parsing(raw, expected):
    assert stack.parse_port(raw) == expected


# --- claims probe -------------------------------------------------------------

def test_claims_against_records(tmp_path):
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    log.append(user="dr.a", agent="assistant-1", workspace="ws_a", action="record.read", obj="client:1")
    log.append(user="dr.a", workspace="ws_a", action="email.send", obj="client:2")            # agent not named
    log.append(user="dr.a", agent="assistant-1", workspace="ws_a", action="record.export", obj="client:9")  # never reported
    transcript = tmp_path / "t.jsonl"
    transcript.write_text("\n".join(json.dumps(c) for c in [
        {"agent": "assistant-1", "workspace": "ws_a", "action": "record.read", "object": "client:1"},
        {"agent": "assistant-1", "workspace": "ws_a", "action": "email.send", "object": "client:2"},
        {"agent": "assistant-1", "workspace": "ws_a", "action": "record.delete", "object": "client:3"},
    ]) + "\n")
    result = claims.run(str(transcript), log.path)
    assert sorted(f.control for f in result.findings) == ["AGENT-1", "LOG-1"]
    assert any("did more than they reported" in note for note in result.inconclusive)
    assert result.checks_for == {"LOG-1": 3, "AGENT-1": 3}


def test_claims_clean_when_log_and_transcript_agree(tmp_path):
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    log.append(user="u", agent="a1", workspace="w", action="x", obj="o")
    t = tmp_path / "t.jsonl"
    t.write_text(json.dumps({"agent": "a1", "workspace": "w", "action": "x", "object": "o"}) + "\n")
    result = claims.run(str(t), log.path)
    assert result.clean and not result.inconclusive


# --- reproduce before report ----------------------------------------------------

def test_a_finding_that_does_not_reproduce_is_not_reported(monkeypatch, fixed_server):
    """One odd response is a theory. It becomes a finding only if it happens again."""
    from patient_zero.probes import common
    from patient_zero.probes import isolation as iso

    real = common.request
    calls = {"n": 0}

    def flaky(target, method, path, token=None, body=None, timeout=20.0):
        resp = real(target, method, path, token, body, timeout)
        if token == "tok-b":
            calls["n"] += 1
            if calls["n"] == 1:  # leak exactly once
                return common.Response(200, json.dumps({"note": CANARY}), {})
        return resp

    monkeypatch.setattr(iso, "request", flaky)
    result = isolation.run(target_for(fixed_server))
    assert result.clean
    assert any("did not reproduce" in note for note in result.inconclusive)


# --- fragility ----------------------------------------------------------------

def test_fragility_ranks_the_source_everything_leans_on():
    data = assess.new("demo", "L1", PROF)
    for cid in ("BASE-1", "BASE-2", "BASE-3", "BASE-4", "BASE-5", "BASE-6"):
        assess.set_status(data, cid, "pass", evidence=["e"], assessor="pat")
    assess.set_status(data, "MAP-1", "pass", evidence=["e"], assessor="lee", independent=True)
    rows = bayes.fragility(data, PROF, MODEL)
    assert rows[0]["source"] == "pat (self)" and len(rows[0]["controls"]) == 6
    assert rows[1]["source"] == "lee (independent)"
    assert rows[0]["belief_lost"] > rows[1]["belief_lost"] > 0


def test_fragility_ignores_failures_and_cli_prints(tmp_path, capsys):
    data = assess.new("demo", "L0", PROF)
    assess.set_status(data, "GATE-1", "fail", note="broken", assessor="pat")
    assert bayes.fragility(data, PROF, MODEL) == []
    a = str(tmp_path / "a.yaml")
    assess.set_status(data, "GATE-2", "pass", evidence=["e"], assessor="pat")
    assess.save(data, a)
    assert main(["fragile", a]) == 0
    assert "pat (self)" in capsys.readouterr().out
