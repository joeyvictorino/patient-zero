# Lab: find and fix what is wrong with a health app

About 45 minutes. For students, new developers and anyone who will build or buy software that touches patient information. You need a laptop with Python 3.9 or newer. You do not need a security background, an account or an API key, and nothing here touches real data.

## Set up (5 minutes)

```
git clone https://github.com/joeyvictorino/patient-zero && cd patient-zero
python3 -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .
```

## Part 1: read the report (10 minutes)

`examples/vibe-clinic` is a small visit-notes app written the way a first draft from an AI coding tool often comes out. Every file is wrong on purpose.

```
pz check examples/vibe-clinic
```

1. How many kinds of mistake did it find? Which three does it say to fix first, and why those?
2. Open `examples/vibe-clinic/src/lib/ai.ts`. Find the lines the report points to. In your own words: who can read the model key?
3. The report ends with "What this could not check". Pick one item. Why can no scan of source files see it?

## Part 2: fix it (15 minutes)

Copy the app somewhere you can edit it:

```
cp -r examples/vibe-clinic /tmp/my-clinic && cd /tmp/my-clinic
```

Fix as many findings as you can, rerunning `pz check .` after each. Aim to clear everything marked CRITICAL and HIGH. Rules:

- Fix the cause. Do not add `pz:ignore` to make a finding disappear.
- One finding cannot be fixed with code. Which one, and what would fix it?

## Part 3: watch a real test (10 minutes)

A scan reads files. A probe talks to a running app. Back in the repository folder:

```
pz demo --brief
```

This starts a deliberately broken clinic app on your own machine, tests it, patches it, and tests it again.

4. After the fix, every test is clean, and the report still says "not approved". Why?
5. The demo seals its evidence and then edits one file. What happens, and why would a clinic care?

## Part 4: the other side of the table (5 minutes)

Read `docs/PITCH-SCORECARD.md`. Imagine you built the app in Part 2 and are pitching it to a clinic.

6. Score yourself honestly on the eight questions. Which would you fix before the pitch?

## What to take away

- The mistakes that sink a health app are ordinary ones, made early: a key in the wrong place, data sent to a company with no agreement, a table anyone can read.
- "Clean" is not "safe". A test that found nothing only tells you about what it could see.
- Nobody can call an app "HIPAA compliant" on the strength of a tool. What you can do is say exactly what was tested and show the evidence.
