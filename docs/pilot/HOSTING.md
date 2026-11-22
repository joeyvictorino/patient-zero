# Hosting a pilot

A pilot needs three things in one place: a test copy of the product, made-up patient records, and patient-zero. This page is for whoever provides the machine.

## What the machine is for

- It runs a **test copy** of the product, or reaches one on a staging address. Never production.
- It holds **only synthetic records** (`pz synth`, or the files `pz pilot init` writes). If a real record is ever seen, testing stops; the rules of engagement say so.
- It is where the probes run from, so its address is the one the product's owner will see in their logs.

## Setting it up

A small virtual machine is plenty: 2 CPUs, 2 GB of memory, any current Linux. Then either:

**With Docker**

```
git clone https://github.com/joeyvictorino/patient-zero && cd patient-zero
docker build -t patient-zero .
mkdir pilot && docker run --rm -v "$PWD/pilot":/pilot patient-zero pilot init /pilot --product "Product name" --base-url https://staging.example.com
```

**Without Docker**

```
python3 -m venv pz && . pz/bin/activate
pip install "git+https://github.com/joeyvictorino/patient-zero#egg=patient-zero[sign]"
pz pilot init pilot --product "Product name" --base-url https://staging.example.com
```

Either way you now have a `pilot/` folder. Open `pilot/PILOT.md` and work down it.

## Keeping the machine itself safe

The machine holds test logins and, later, a signing key. Treat it like a small server that matters:

- [ ] Reachable only by the people in the pilot: a firewall rule or VPN, no public SSH with passwords.
- [ ] Disk encryption on, automatic security updates on.
- [ ] Each person has their own login. No shared account.
- [ ] Outbound access limited to the hosts in `target.yaml` and the package index. patient-zero itself needs no network except to reach the product under test.
- [ ] The test logins are for test tenants only and are deleted when the pilot ends.
- [ ] The signing key (`pz keygen`) stays on this machine, mode 0600, and out of any repository.
- [ ] When the pilot ends: copy out the `pilot/` folder (it has the evidence and the report), then delete the machine.

`pz check .` run in the product's source folder is separate: it reads files, needs no network, and can run on a developer's laptop.

## What the owner of the product provides

Two test tenants, one login for each, and an hour. `pilot/rules-of-engagement.md` is theirs to sign, and nothing runs until `target.yaml` says `authorized: true`.

## What comes out

`pilot/pilot-report.md` in plain language, dated evidence under `pilot/evidence/`, and an updated `assessment.yaml`. `pz sandbox pilot` shows which sandbox entry and exit criteria the pilot meets.
