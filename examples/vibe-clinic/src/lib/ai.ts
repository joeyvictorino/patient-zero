import OpenAI from "openai";

// The key is read from a public variable, so it ships to every visitor's browser.
const client = new OpenAI({
  apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY,
  dangerouslyAllowBrowser: true,
});

export async function summarizeVisit(patient: { id: string; name: string; diagnosis: string }, transcript: string) {
  console.log("summarizing visit for", patient.name, patient.diagnosis);
  const reply = await client.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: `Summarize this visit for ${patient.name}:\n${transcript}` }],
  });
  localStorage.setItem("last_patient_note", reply.choices[0].message.content ?? "");
  return reply.choices[0].message.content;
}
