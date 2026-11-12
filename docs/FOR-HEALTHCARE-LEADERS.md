# For healthcare leaders: one page

**The problem.** AI vendors are arriving at every practice, clinic and hospital. Each says it is safe for patient data. Most small organizations have no way to check, and most small vendors cannot afford the months of consulting it takes to prove it. Useful tools stall, and risky ones get through on a handshake.

**What patient-zero is.** A free, open list of 43 safeguards an AI product should have before it touches patient information, written twice: once for the engineers who build the product, and once in plain language for the people who buy it. It comes with software that tests some of those safeguards automatically and packages the proof so it cannot be quietly edited afterward.

**What you can do with it today, without any technical staff.**

1. **Send the vendor the questionnaire.** [`VENDOR-QUESTIONNAIRE.md`](VENDOR-QUESTIONNAIRE.md) has every safeguard as a plain question, with what a good answer comes with. A vendor who says yes but cannot produce the evidence has not answered.
2. **Ask for a sealed report.** A vendor who uses patient-zero can hand you a one-page summary in plain language and a signed bundle of evidence. If any file in the bundle is changed after signing, verification fails.
3. **Check the Nevada items.** [`NEVADA.md`](NEVADA.md) covers what Nevada law adds for AI: the 2025 limits on AI in mental and behavioral health care (AB 406) and the consumer health data law (SB 370).

**What it costs.** Nothing. It is open source under the MIT license. No account, no fee, and it sends no data anywhere.

**What it is not.**

- It is not a HIPAA certification. No such certification exists; the federal government does not issue or recognize one.
- It is not legal advice and does not replace a Business Associate Agreement or your own counsel.
- It is new. As of this writing it has been tested only against its own demonstration app, not yet on a real product in a real clinic. The repository lists every known limit in a folder called `things-that-do-not-work`.

**What would make it better.** One vendor and one member organization willing to run it together and publish what they learn. Clinicians, compliance officers and health lawyers willing to tell us where the plain-language questions are wrong.

**Who is behind it.** Joey Victorino, a security practitioner in Henderson, Nevada. github.com/joeyvictorino/patient-zero
