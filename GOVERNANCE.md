# Governance

patient-zero has one maintainer today. This document says how decisions are made now, and what changes as more people join, so nobody has to guess later.

## What is governed

| Part | Where | Who decides |
| --- | --- | --- |
| The standard: profile, spec, test vectors | `patient_zero/data/controls.yaml`, `spec/`, `patient_zero/data/vectors/` | Maintainers, after the review below |
| The belief model numbers | `patient_zero/data/belief.yaml` | Maintainers, on evidence (see `calibration-data/`) |
| State overlays | `patient_zero/data/overlays/` | Maintainers, with a reviewer who practices in that state |
| The reference implementation | everything else | Any maintainer, by normal code review |
| The name and badge | `TRADEMARK.md` | The project lead |

The standard is held to a higher bar than the code, because other people build on it and vendors make claims against it.

## Changing the standard

A change to a control, to the spec or to a test vector:

1. is proposed as a pull request that says what changes and why, and what evidence or source it rests on
2. stays open for at least 14 days, so people affected can object
3. needs approval from a maintainer and, where a family has a named reviewer in `MAINTAINERS.md`, from that reviewer
4. changes the profile or spec version, and is recorded in `CHANGELOG.md`

A fix to a citation or a typo that does not change what is required can merge without the waiting period.

No change may make the tooling describe a product as compliant, certified or passed, let a probe record `pass`, or count a run that tested nothing as clean. Those three rules are the point of the project, and removing one needs every maintainer to agree.

## Roles

- **Contributor**: anyone who opens an issue or pull request.
- **Reviewer**: a person with standing in a field (health privacy law, clinical practice, security assessment, a state's rules) who reviews one family or overlay. Named in `MAINTAINERS.md`. A reviewer need not write code.
- **Maintainer**: can merge. Becomes one by sustained, careful contribution and the agreement of the existing maintainers.
- **Project lead**: Joey Victorino. Breaks ties and holds the name. This role exists because the project is young; see below.

## Conflicts of interest

A maintainer or reviewer who works for, or is paid by, a company that seals assessments with patient-zero says so in `MAINTAINERS.md`, and does not approve changes that would loosen a control their own product fails.

## What changes as the project grows

- **At three maintainers from at least two organizations:** decisions on the standard move to a majority of maintainers, and the project lead keeps only the tie-break.
- **When vendors rely on the badge commercially:** the name and the standard should move to a neutral home, such as a foundation, so that no single company controls what "ran patient-zero" means. Which one is an open decision.
- **Open decision:** whether the spec text should carry a documentation license (such as CC BY 4.0) separate from the MIT license on the code. Today everything is MIT.

## Conduct

See `CODE_OF_CONDUCT.md`. Security reports go through `SECURITY.md`, not public issues.
