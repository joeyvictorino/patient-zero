"use client";
import posthog from "posthog-js";

// Starts recording as soon as the page opens. Nobody is asked.
export async function startVisitRecording() {
  const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  const recorder = new MediaRecorder(stream);
  recorder.start();
  posthog.capture("visit_started", { page: window.location.href });
  return recorder;
}
