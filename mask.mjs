/**
 * Registering values with the runner's log masker.
 *
 * THIS FILE IS PUBLISHED — it runs inside every customer's pipeline.
 *
 * Masking is a courtesy, not a security control, and the docs say so. It stops a value that
 * reaches a log by accident from being readable there; it stops nothing that is trying. The runner
 * covers base64 at all three alignments, URL, JSON, XML and command-line encodings of a registered
 * value automatically — but NOT hex, case changes, double-base64, or anything derived from it.
 * CVE-2025-30066's payload double-base64'd its haul straight past this.
 *
 * Two rules the shape below exists for:
 *
 *  1. Register each LINE as well as the whole value. A multi-line secret printed one line at a
 *     time matches no whole-value entry, which is how CVE-2021-32074 leaked private keys through
 *     an action that registered only the blob. A multi-line value cannot itself be registered —
 *     `::add-mask::` reads to the end of a line — so for those the lines are all there is.
 *  2. Never treat a JSON blob as one secret. Registering the document leaves every leaf inside it
 *     unmasked the moment a tool prints one field.
 */

/** Below this a mask is worse than none: it would redact unrelated output wherever it matched. */
const MIN_MASKABLE = 3;

/** Below this masking is technically registered and practically meaningless. Say so out loud. */
const WEAK_MASK = 8;

/**
 * Workflow-command escaping. Without it a value containing a literal `%0A` is un-escaped by the
 * runner into a newline, and what gets registered is not the value we hold.
 */
function escapeData(value) {
  return value.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

/** Every distinct string inside a parsed JSON document, however deep. */
function jsonLeaves(parsed, into) {
  if (typeof parsed === "string") {
    into.add(parsed);
    return;
  }
  if (Array.isArray(parsed)) {
    for (const item of parsed) jsonLeaves(item, into);
    return;
  }
  if (parsed !== null && typeof parsed === "object") {
    for (const item of Object.values(parsed)) jsonLeaves(item, into);
  }
}

/** Everything that has to be registered for one retrieved value, longest first. */
export function maskCandidates(value) {
  const candidates = new Set();
  if (!value.includes("\n")) candidates.add(value);
  for (const line of value.split("\n")) {
    const trimmed = line.trim();
    if (trimmed) candidates.add(trimmed);
  }
  try {
    const parsed = JSON.parse(value);
    if (parsed !== null && typeof parsed === "object") jsonLeaves(parsed, candidates);
  } catch {
    // Not JSON. The whole value and its lines are already registered.
  }
  // Longest first: the runner replaces in registration order, so registering a substring first
  // would shred the longer entry into `***`-joined fragments in the log.
  return [...candidates]
    .filter((c) => c.length >= MIN_MASKABLE)
    .sort((a, b) => b.length - a.length);
}

/**
 * Register `value` and warn when masking it cannot mean much. `emit` writes a workflow command;
 * `warn` writes a warning annotation. Both are injected so this stays testable without a runner.
 */
export function mask(value, label, emit, warn) {
  for (const candidate of maskCandidates(value)) emit(`::add-mask::${escapeData(candidate)}`);
  if (value.trim().length < MIN_MASKABLE) {
    warn(
      `${label} is under ${MIN_MASKABLE} characters, so it was NOT masked — a mask that short would redact unrelated log output.`,
    );
    return;
  }
  if (value.trim().length < WEAK_MASK) {
    warn(
      `${label} is under ${WEAK_MASK} characters. It is masked, but a value that short is guessable and masking it means very little.`,
    );
  }
}
