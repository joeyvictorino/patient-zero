# Giving a talk about patient-zero

Ten minutes, for a room that is mostly not engineers: clinic leaders, legislators, students, founders. The slides are [`slides.html`](slides.html). They work offline; open the file in any browser.

- **Next slide:** right arrow, space, or click the right two thirds of the screen. **Back:** left arrow or click the left third.
- **PDF handout:** print from the browser. Each slide becomes one landscape page.
- **Jump to a slide:** add `#7` to the address.

Rewrite the words below into your own. They are a track to follow, not a script to read.

## The one idea

If the room remembers a single sentence, it should be: **don't ask "is it compliant?", ask who tested what, on which version, and when.** Every slide serves that.

## Track

| Slide | Time | Say |
| --- | --- | --- |
| 1. "Is it HIPAA compliant?" | 0:00 | Start with the question itself. Ask who in the room has asked it or been asked it. |
| 2. A clinic asks one question | 0:30 | The vendor says yes and points to a badge. Then the fact most people do not know: no HIPAA certification exists. Pause there. |
| 3. 2.5% | 1:30 | A checklist feels like certainty. If each tick is 90% likely to be true, 35 ticks give a 2.5% chance that nothing is broken. This is why "we passed the checklist" should not reassure anyone. |
| 4. Who tested what | 2:30 | The better question, and the four kinds of people in the room. Find your row. |
| 5. A first draft | 3:15 | **Live demo 1**, or the slide. This is what an app looks like when someone builds it quickly with an AI tool. Read the first finding aloud in full: why it matters, and the fix. |
| 6. Clean is not a pass | 5:00 | **Live demo 2**, or the slide. The tool refuses to say "approved" even when every test is clean. That refusal is the design. |
| 7. What the buyer sees | 6:15 | **Live demo 3**, or the slide. No install. Click the edited sample and let the room see it get caught. |
| 8. The badge | 7:15 | It cannot be green and cannot say compliant. It gives counts and has to link to proof. |
| 9. Four questions | 7:45 | Read all four. These work with no software at all. Hand out the full ten if you printed them. |
| 10. What is weak | 8:30 | Say it plainly and do not rush. This slide is why the rest is believable. |
| 11. What would change that | 9:15 | The ask. One pilot, one reviewer per topic, their hardest question. |
| 12. Ask who tested what | 9:45 | Repeat the one idea. Stop talking. |

## Live demos

Do them only if you have rehearsed on the machine you will present from. Each has a slide that shows the same thing, so skipping a demo costs nothing.

**The day before**

```
git clone https://github.com/joeyvictorino/patient-zero && cd patient-zero
python3 -m venv .venv && . .venv/bin/activate && pip install -e .
pz check examples/vibe-clinic && pz demo --brief       # run both once, start to finish
```

- Set the terminal font to at least 20 points and the window to about 100 columns. Use a light background; projectors wash out dark themes.
- Open `docs/verify/index.html` and `docs/talk/slides.html` in browser tabs. Both work with no network. Turn the network off and check.
- Clear the terminal, and turn off notifications.

**Demo 1, about 90 seconds**

```
pz check examples/vibe-clinic | less
```

Stop on the first screen. Read finding 1. Scroll once to show there are twelve, then to the end to show "What this could not check". Say that the list of what it cannot see is printed every time, on purpose.

**Demo 2, about 60 seconds**

```
pz demo --brief
```

It takes about ten seconds to run. Talk over it: it is starting a deliberately broken clinic app on this laptop, testing it, patching it, testing again. Point at "Still not approved: 0 of 51 are confirmed."

**Demo 3, about 60 seconds**

In the browser tab with the verify page: click **Try a sample**, point at the counts and at who signed. Then click **Try a sample that was edited after signing**, and let the red line speak.

**If something breaks:** say "the slide shows what you would have seen", go to the slide, and keep going. Do not debug in front of the room.

## Questions you will get

Short answers. [`FAQ.md`](../FAQ.md) has the long ones.

- **"So is anything HIPAA compliant?"** Organizations comply or do not, as judged after the fact by a regulator. Nobody certifies it in advance. What you can have is evidence.
- **"Does this replace our security assessment?"** No. It makes the assessment's results specific and hard to quietly change, and it gives a small clinic a way to ask good questions without one.
- **"What does it cost?"** Nothing. It is open source and runs offline.
- **"Who is behind it? Who decides what is on the list?"** One maintainer today, with written rules for how the list changes and open seats for a lawyer, a clinician and an assessor. That is the biggest weakness, and it is why the ask on slide 11 is for reviewers.
- **"Can a vendor just lie?"** Yes. A signature shows the claim has not changed, not that it is true. But it becomes a specific, dated, signed false statement with counts in it, which is different from a logo.
- **"Is the AI going to check the AI?"** The tests are ordinary code that a model cannot talk its way past. A person signs the result.
- **"What should the legislature do?"** The project takes no position on any bill. The ten questions are ones any rule would need answers to.
- **"We are a small practice with no IT staff."** Send the vendor the question list and ask for the file. Checking it takes a browser.

## Handouts worth printing

- [`LEGISLATOR-BRIEF.md`](../LEGISLATOR-BRIEF.md): the ten questions, with what state rules say today.
- [`FOR-HEALTHCARE-LEADERS.md`](../FOR-HEALTHCARE-LEADERS.md) and its Spanish version: one page for someone who buys.
- [`PITCH-SCORECARD.md`](../PITCH-SCORECARD.md): if there is a pitch session.

## Afterward

Write down the questions you could not answer. Each one is either a gap for `known-gaps/` or a line for the FAQ.
