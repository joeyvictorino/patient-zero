# Lab: instructor notes

## Before the session

- Run the setup yourself on the kind of machine students will use. The lab needs Python 3.9 or newer and git, and no network once the repository is cloned and installed.
- If laptops are locked down, the same lab works from one shared machine or the Docker image (`docs/pilot/HOSTING.md`).
- Allow 45 minutes, or 75 with discussion.

## Answers

**Part 1**

1. Twelve kinds. The first three are the model called from the browser, the key exposed through a public variable, and the committed `.env`. They come first because they are critical: each hands a secret or patient data to anyone, with no skill needed.
2. Everyone who loads the page. A variable with a public prefix is compiled into the JavaScript sent to every visitor.
3. Any of them. The strongest example: whether one clinic can read another's records depends on how the running app checks each request, which is behavior and not text. `src/app/api.py` has exactly this flaw (no ownership check on `/notes/{note_id}`) and the scan does not report it.

**Part 2**

A reasonable set of fixes:

- `src/lib/ai.ts`: move the model call to a server route; read the key from a server-only variable; remove `dangerouslyAllowBrowser`; log an id and not `patient.name` or `patient.diagnosis`; do not put the note in `localStorage`.
- `src/app/visit/recorder.tsx`: ask everyone before recording, store the answer, allow the visit without recording; remove the analytics tracker from pages patients use.
- `src/app/api.py`: list the allowed origins; remove `verify=False`.
- `.env`: remove it from the repository, add it to `.gitignore`, and treat its values as leaked.
- `supabase/migrations`: enable row level security on `visit_notes`; replace `using (true)` with a policy that limits rows to their clinic.
- `docker-compose.yml`: publish the database and the model server on `127.0.0.1` only; remove the wildcard origin.

The finding that code cannot fix is the model provider: it needs a signed Business Associate Agreement, recorded in `register.yaml`. A student who adds a register entry saying `baa: true` to clear the finding has made a false record. That is worth stopping the room for.

Recording also still shows after a good fix, because the scan sees that audio is captured and cannot see that consent is asked. That is a fair moment to talk about what a pattern match can and cannot know, and about `pz:ignore` with a reason.

**Part 3**

4. A probe can fail a safeguard and cannot pass one. Three requests that found nothing are weak evidence. A person has to look at the evidence and sign.
5. Verification fails and names the changed file. A clinic cares because a report that can be quietly edited after the fact is worth nothing.

**Part 4**

6. There is no right score. Look for students who give themselves a 1 with a plan over a 2 they cannot support.

## Discussion prompts

- The app in Part 1 "works". Who is harmed if it ships as it is, and would they ever find out?
- Which of these mistakes would an AI coding assistant make on its own, and which would it catch if asked?
- Who should be allowed to say a health app is safe to use?

## Variations

- **Pitch session.** Teams fix the app, then pitch it for three minutes. Judges use `docs/PITCH-SCORECARD.md`.
- **Buyers' version**, for clinic staff and no laptops: hand out `docs/VENDOR-QUESTIONNAIRE.md`, show `pz demo --brief` on a projector, and have the room decide which five questions they would send a vendor first.
- **Policy version**: use `docs/LEGISLATOR-BRIEF.md`. For each question, ask who should have to answer it, and to whom.
