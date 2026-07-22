import { types as nodeTypes } from "node:util";
import type { BountyDatabase } from "../../stores/db/database.js";
import { hasImmediateTransaction } from "../../stores/db/database.js";
import { BountyPilotError } from "../../utils/errors.js";
import { createId } from "../../utils/ids.js";
import { maskSecrets } from "../../utils/secrets.js";
import { nowIso } from "../../utils/time.js";

export type ActionReviewDecision = "approved" | "blocked" | "executed" | "failed";

export type ActionReviewSource = "human" | "policy";

export interface ActionReviewRecord {
  id: string;
  actionId: string;
  jobId?: string;
  decision: ActionReviewDecision;
  note?: string;
  createdAt: string;
  reviewerId?: string;
  source?: ActionReviewSource;
  reviewedAt?: string;
  expiresAt?: string;
  scopeHash?: string;
  policyHash?: string;
  actionHash?: string;
  contextHash?: string;
  invalidatedAt?: string;
  invalidationReason?: string;
}

export interface NewActionReviewInput {
  actionId: string;
  jobId?: string;
  decision: ActionReviewDecision;
  note?: string;
}

/**
 * Public input for the in-transaction approval insert primitive.
 *
 * The store generates the trusted review ID; no caller-supplied
 * `id` is permitted (a runtime-cast `id` is rejected with
 * ACTION_APPROVAL_INVALID and writes zero rows).
 */
export interface CompleteApprovalReviewInput {
  actionId: string;
  jobId: string;
  decision: "approved";
  reviewerId: string;
  source: ActionReviewSource;
  reviewedAt: string;
  expiresAt: string;
  scopeHash: string;
  policyHash: string;
  actionHash: string;
  contextHash: string;
  note?: string;
}

/**
 * Trusted, non-authorizing review written after an action reached
 * `outcome_unknown`.  The store owns the id/source/expiry fields; callers
 * provide only the exact provenance and human attestation that were already
 * validated by the lifecycle boundary.
 */
export interface ReconciliationReviewInput {
  actionId: string;
  jobId: string;
  decision: "executed" | "failed";
  reviewerId: string;
  reviewedAt: string;
  scopeHash: string;
  policyHash: string;
  actionHash: string;
  contextHash: string;
  note: string;
}

export type ActionReviewInvalidationReason =
  | "review_expired"
  | "scope_drift"
  | "policy_drift"
  | "action_hash_mismatch"
  | "context_hash_mismatch"
  | "scope_blocked"
  | "policy_blocked";

export interface InvalidateApprovalInput {
  reviewId: string;
  actionId: string;
  jobId: string;
  invalidatedAt: string;
  invalidationReason: ActionReviewInvalidationReason;
}

export interface InvalidateApprovalResult {
  readonly changes: 0 | 1;
}

const POLICY_REVIEWER_ID = "system:policy-gate";
// 1..256 Unicode code points per the v2 review contract.
const REVIEWER_CODE_POINT_MIN = 1;
const REVIEWER_CODE_POINT_MAX = 256;
const HASH_REGEX = /^(?!0{64}$)[0-9a-f]{64}$/;
const CODE_POINT_REGEX = /[\0-\u001F\u007F]/u;
const STANDALONE_LOWER_HEX64 = /(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])/g;

// Module-level lexical constants captured at module evaluation time.
// These are used by the hardened validator so every read of `input`
// goes through the same trusted intrinsics — never through any
// attacker-controlled hook. None of these references may be re-bound
// inside the validator.
const GET_PROTO: (value: unknown) => unknown = Object.getPrototypeOf;
const GET_OWN_DESCRIPTORS: (value: unknown) => PropertyDescriptorMap = Object.getOwnPropertyDescriptors;
const GET_OWN_DESCRIPTOR: (value: unknown, key: PropertyKey) => PropertyDescriptor | undefined =
  Object.getOwnPropertyDescriptor;
const GET_OWN_PROPERTY_NAMES: (value: unknown) => string[] = Object.getOwnPropertyNames;
const GET_OWN_PROPERTY_SYMBOLS: (value: unknown) => symbol[] = Object.getOwnPropertySymbols;
const IS_PROXY: (value: unknown) => boolean = nodeTypes.isProxy;

const INVALIDATION_REASONS: ReadonlySet<ActionReviewInvalidationReason> = new Set([
  "review_expired",
  "scope_drift",
  "policy_drift",
  "action_hash_mismatch",
  "context_hash_mismatch",
  "scope_blocked",
  "policy_blocked",
]);

// Fixed, secret-free error message used for every hostile-input
// rejection path in the hardened validator. The contract forbids any
// cause, String(error), error.message, or input data from appearing
// in the message string.
const HOSTILE_INPUT_MESSAGE = "CompleteApprovalReviewInput must be a non-null object with own data descriptors";

function invalidApproval(message: string): BountyPilotError {
  // Generic, secret-free code per §10.
  return new BountyPilotError(message, "ACTION_APPROVAL_INVALID");
}

function transactionRequired(): BountyPilotError {
  return new BountyPilotError(
    "ActionReviewStore.insertApprovalInTransaction requires an active withImmediateTransaction on the same handle",
    "ACTION_REVIEW_TRANSACTION_REQUIRED",
  );
}

function invalidationTransactionRequired(): BountyPilotError {
  return new BountyPilotError(
    "ActionReviewStore.invalidateApprovalInTransaction requires an active withImmediateTransaction on the same handle",
    "ACTION_REVIEW_TRANSACTION_REQUIRED",
  );
}

function reconciliationTransactionRequired(): BountyPilotError {
  return new BountyPilotError(
    "ActionReviewStore.insertReconciliationInTransaction requires an active withImmediateTransaction on the same handle",
    "ACTION_REVIEW_TRANSACTION_REQUIRED",
  );
}

function invalidReconciliationInput(): BountyPilotError {
  return new BountyPilotError(
    "Action reconciliation review input is invalid.",
    "ACTION_APPROVAL_INVALID",
  );
}

function reconciliationWriteInvalid(): BountyPilotError {
  return new BountyPilotError(
    "Action reconciliation review write did not affect exactly one row.",
    "ACTION_RECORD_INVALID",
  );
}

function invalidInvalidationInput(): BountyPilotError {
  return new BountyPilotError(
    "Action review invalidation input is invalid.",
    "ACTION_APPROVAL_INVALID",
  );
}

function invalidInvalidationCount(): BountyPilotError {
  return new BountyPilotError(
    "Action review invalidation changed an invalid number of rows.",
    "ACTION_RECORD_INVALID",
  );
}

// Two-layer hostile-input read for a single field of the captured
// descriptor map. ALL property accesses go through the captured
// Object.getOwnPropertyDescriptor intrinsic — never direct dot/bracket
// syntax on a descriptor object, which would walk the prototype chain
// or invoke accessors.
//
// Layer 1: the OUTER descriptor for `key` on the descriptor map. The
//   map is the fresh result of Object.getOwnPropertyDescriptors(input),
//   so for a real own key its outer is a plain data descriptor whose
//   `value` slot holds the INNER PropertyDescriptor (the descriptor
//   that describes input[key]). If the outer is absent, the input has
//   no own `key`.
//
// Layer 2: the INNER descriptor. We acquire it ONLY through the
//   captured intrinsic on the outer descriptor's own `value` slot
//   (treated as an ordinary object). Presence of an own `value` slot
//   on the outer means the input's descriptor for `key` is itself a
//   data descriptor; absence means it is an accessor or otherwise
//   non-data, and we reject without ever touching a getter.
//
// Returns:
//   - "ABSENT"   no own `key` on the input;
//   - "ACCESSOR" own `key` is accessor / non-data, OR the snapshot
//                 itself is malformed (the outer had no own `value`
//                 slot). No getter is invoked either way;
//   - { value }  the actual input field value, safely extracted from
//                 the inner descriptor's own `value` slot.
type ReadResult =
  | { kind: "ABSENT" }
  | { kind: "ACCESSOR" }
  | { kind: "DATA"; value: unknown };

function readField(
  map: PropertyDescriptorMap,
  key: PropertyKey,
  getDescriptor: (value: unknown, k: PropertyKey) => PropertyDescriptor | undefined,
): ReadResult {
  // Layer 1: outer descriptor for the map entry.
  const outer = getDescriptor(map, key);
  if (outer === undefined) {
    return { kind: "ABSENT" };
  }
  // Acquire outer's own `value` slot via the captured intrinsic. A
  // missing own `value` slot on the outer means the snapshot itself is
  // impossible to interpret safely — treat as accessor (no invocation).
  const outerValueSlot = getDescriptor(outer, "value");
  if (outerValueSlot === undefined) {
    return { kind: "ACCESSOR" };
  }
  const inner = outerValueSlot.value;
  if (inner === null || typeof inner !== "object") {
    return { kind: "ABSENT" };
  }
  // Layer 2: acquire the inner descriptor's own `value` slot via the
  // captured intrinsic. Presence of an own `value` slot means the
  // input's descriptor for `key` is a data descriptor; absence means
  // it is an accessor.
  const innerValueSlot = getDescriptor(inner, "value");
  if (innerValueSlot === undefined) {
    return { kind: "ACCESSOR" };
  }
  return { kind: "DATA", value: innerValueSlot.value };
}

function countUnicodeCodePoints(value: string): number {
  // Array.from iterates by Unicode code points, NOT UTF-16 code units.
  return Array.from(value).length;
}

function isCanonicalIsoTimestamp(value: string): boolean {
  // Canonical = exactly the value produced by Date#toISOString().
  // Parse must succeed AND round-trip to the identical string.
  if (typeof value !== "string" || value.length === 0) {
    return false;
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return false;
  }
  return parsed.toISOString() === value;
}

function isValidHash(value: unknown): value is string {
  return typeof value === "string" && HASH_REGEX.test(value);
}

function validateReviewerForSource(rawReviewer: unknown, source: ActionReviewSource): string {
  if (typeof rawReviewer !== "string") {
    throw invalidApproval("reviewerId must be a string");
  }
  // Hardening: inspect the RAW input for C0/DEL first, so trim-removable
  // controls (TAB, LF, VT, FF, CR) at the boundaries are rejected before
  // they can be silently stripped by String.prototype.trim. Then apply
  // the existing trim/canonical/1..256 code-point policy.
  if (CODE_POINT_REGEX.test(rawReviewer)) {
    throw invalidApproval("reviewerId must not contain U+0000..U+001F or U+007F");
  }
  if (source === "policy") {
    // Policy source requires the RAW reviewer to be EXACTLY the literal,
    // with no surrounding spaces or trim-removable controls.
    if (rawReviewer !== POLICY_REVIEWER_ID) {
      throw invalidApproval("policy reviewerId must be exactly system:policy-gate");
    }
    return POLICY_REVIEWER_ID;
  }
  // source === "human": trim after the raw C0 check, then enforce
  // trimmed-nonempty and the 1..256 code-point cap.
  const trimmed = rawReviewer.trim();
  if (trimmed.length === 0) {
    throw invalidApproval("reviewerId must be nonempty when trimmed");
  }
  const codePoints = countUnicodeCodePoints(trimmed);
  if (codePoints < REVIEWER_CODE_POINT_MIN || codePoints > REVIEWER_CODE_POINT_MAX) {
    throw invalidApproval("reviewerId must be 1..256 Unicode code points when trimmed");
  }
  if (trimmed === POLICY_REVIEWER_ID) {
    throw invalidApproval("human reviewerId must not be system:policy-gate");
  }
  return trimmed;
}

function validateTimestampPair(reviewedAt: unknown, expiresAt: unknown): { reviewedAt: string; expiresAt: string } {
  if (typeof reviewedAt !== "string") {
    throw invalidApproval("reviewedAt must be a string");
  }
  if (typeof expiresAt !== "string") {
    throw invalidApproval("expiresAt must be a string");
  }
  if (!isCanonicalIsoTimestamp(reviewedAt)) {
    throw invalidApproval("reviewedAt must be the canonical Date#toISOString() form");
  }
  if (!isCanonicalIsoTimestamp(expiresAt)) {
    throw invalidApproval("expiresAt must be the canonical Date#toISOString() form");
  }
  // Compare by parsed epoch milliseconds so the order is independent
  // of lexicographic quirks in ISO-8601 extended-year prefixes (the
  // leading '+' for years >= 10000 sorts before digits in ASCII). The
  // exact supplied strings are still persisted verbatim below.
  const reviewedMs = new Date(reviewedAt).getTime();
  const expiresMs = new Date(expiresAt).getTime();
  if (!(expiresMs > reviewedMs)) {
    throw invalidApproval("expiresAt must be strictly later than reviewedAt");
  }
  return { reviewedAt, expiresAt };
}

// Hardened structural validator for CompleteApprovalReviewInput.
//
// Reflects the input once via Object.getPrototypeOf +
// Object.getOwnPropertyDescriptors, then reads every field exclusively
// from the captured descriptor map. The input reference is never
// touched again after the snapshot. Any trap (Proxy getPrototypeOf,
// revoked Proxy, non-data descriptor, throwing descriptor conversion)
// collapses to a single secret-free ACTION_APPROVAL_INVALID message.
//
// Required fields are read through their own DATA descriptors:
//   - missing     -> propagates to the existing fixed validator (or
//                    becomes a type error that throws invalidApproval);
//   - accessor    -> immediate reject without invoking it;
//   - data value  -> used directly.
// Optional `note`: absent -> undefined; own data value undefined -> valid.
//
// Caller-supplied `id` is rejected: an OWN `id` descriptor (any kind,
// even undefined or accessor) is invalid; an INHERITED `id` is ignored.
function validateCompleteApprovalInput(input: unknown): CompleteApprovalReviewInput {
  if (input === null || typeof input !== "object") {
    throw invalidApproval(HOSTILE_INPUT_MESSAGE);
  }

  // Single try/catch: ANY exception raised by the hostile-input
  // reflection sequence (getPrototypeOf, getOwnPropertyDescriptors,
  // getOwnPropertyDescriptor, or descriptor conversion) becomes the
  // same fixed secret-free message. Never include cause, the error
  // object, its message, or any input data.
  let proto: unknown;
  let descriptorMap: PropertyDescriptorMap;
  try {
    // `Object.getPrototypeOf` and `Object.getOwnPropertyDescriptors` both
    // invoke Proxy traps. Reject Proxy and revoked-Proxy envelopes through
    // Node's trap-free brand check before performing either reflection step.
    if (IS_PROXY(input)) {
      throw invalidApproval(HOSTILE_INPUT_MESSAGE);
    }
    proto = GET_PROTO(input);
    if (proto !== Object.prototype && proto !== null) {
      throw invalidApproval(HOSTILE_INPUT_MESSAGE);
    }
    descriptorMap = GET_OWN_DESCRIPTORS(input);
  } catch {
    throw invalidApproval(HOSTILE_INPUT_MESSAGE);
  }

  // After this point `input` is NEVER read again. All field reads go
  // through `descriptorMap` + `GET_OWN_DESCRIPTOR`. The descriptor map
  // is a normal object (inherits Object.prototype), so we read its own
  // entries with the captured `GET_OWN_DESCRIPTOR` rather than with
  // dot/bracket syntax on the map (which would also consult the
  // prototype chain).

  // Caller-supplied id: any OWN `id` descriptor — regardless of
  // whether the input id is a data or accessor descriptor — is
  // rejected. An INHERITED `id` is ignored (the snapshot has no own
  // entry for it). The decision is based solely on the OUTER
  // descriptor's presence for the map entry.
  const ownId = readField(descriptorMap, "id", GET_OWN_DESCRIPTOR);
  if (ownId.kind !== "ABSENT") {
    throw invalidApproval("CompleteApprovalReviewInput must not supply an id");
  }

  // Each required field: must be an own DATA descriptor. An own
  // accessor is rejected without invoking the getter. A missing
  // descriptor flows to the existing fixed validator (which will
  // throw a type-shape rejection).
  function requireOwnData(key: PropertyKey): unknown {
    const r = readField(descriptorMap, key, GET_OWN_DESCRIPTOR);
    if (r.kind === "ABSENT") {
      return undefined;
    }
    if (r.kind === "ACCESSOR") {
      throw invalidApproval(`CompleteApprovalReviewInput.${String(key)} must be an own data descriptor`);
    }
    return r.value;
  }

  const actionId = requireOwnData("actionId");
  const jobId = requireOwnData("jobId");
  const decision = requireOwnData("decision");
  const reviewerId = requireOwnData("reviewerId");
  const source = requireOwnData("source");
  const reviewedAt = requireOwnData("reviewedAt");
  const expiresAt = requireOwnData("expiresAt");
  const scopeHash = requireOwnData("scopeHash");
  const policyHash = requireOwnData("policyHash");
  const actionHash = requireOwnData("actionHash");
  const contextHash = requireOwnData("contextHash");

  // Optional note: absent -> undefined; own data value undefined ->
  // valid. An own accessor for `note` is still rejected.
  let note: string | undefined;
  const noteRead = readField(descriptorMap, "note", GET_OWN_DESCRIPTOR);
  if (noteRead.kind === "ACCESSOR") {
    throw invalidApproval("CompleteApprovalReviewInput.note must be an own data descriptor");
  } else if (noteRead.kind === "DATA") {
    note = noteRead.value as string | undefined;
  }

  // actionId / jobId: not strings OR trim-empty both fail.
  if (typeof actionId !== "string" || actionId.trim().length === 0) {
    throw invalidApproval("actionId must be a nonempty string");
  }
  if (typeof jobId !== "string" || jobId.trim().length === 0) {
    throw invalidApproval("jobId must be a nonempty string");
  }

  // decision must be EXACTLY the literal "approved".
  if (decision !== "approved") {
    throw invalidApproval("decision must be exactly 'approved'");
  }

  // source must be exactly "human" or "policy".
  if (source !== "human" && source !== "policy") {
    throw invalidApproval("source must be exactly 'human' or 'policy'");
  }

  // note must be either undefined OR a string (no other types).
  if (note !== undefined && typeof note !== "string") {
    throw invalidApproval("note must be undefined or a string");
  }

  // Reviewer validation (also enforces source/reviewer structural link).
  const trimmedReviewer = validateReviewerForSource(reviewerId, source);

  // Timestamps: canonical + strict ordering (parsed epoch compare).
  const ts = validateTimestampPair(reviewedAt, expiresAt);

  // All four hashes must be the nonzero 64 lowercase-hex form.
  if (!isValidHash(scopeHash)) {
    throw invalidApproval("scopeHash must be 64 lowercase hex characters and not the all-zero sentinel");
  }
  if (!isValidHash(policyHash)) {
    throw invalidApproval("policyHash must be 64 lowercase hex characters and not the all-zero sentinel");
  }
  if (!isValidHash(actionHash)) {
    throw invalidApproval("actionHash must be 64 lowercase hex characters and not the all-zero sentinel");
  }
  if (!isValidHash(contextHash)) {
    throw invalidApproval("contextHash must be 64 lowercase hex characters and not the all-zero sentinel");
  }

  return {
    // Identifiers are validated by trimmed-nonempty but PERSISTED with their
    // supplied value (no trimming of actionId/jobId).
    actionId: actionId as string,
    jobId: jobId as string,
    decision: "approved",
    reviewerId: trimmedReviewer,
    source,
    reviewedAt: ts.reviewedAt,
    expiresAt: ts.expiresAt,
    scopeHash,
    policyHash,
    actionHash,
    contextHash,
    note,
  };
}

function validateInvalidationInput(input: unknown): InvalidateApprovalInput {
  let names: string[];
  let symbols: symbol[];
  let descriptors: PropertyDescriptorMap;
  try {
    if (input === null || typeof input !== "object" || IS_PROXY(input)) {
      throw invalidInvalidationInput();
    }
    const proto = GET_PROTO(input);
    if (proto !== Object.prototype && proto !== null) {
      throw invalidInvalidationInput();
    }
    names = GET_OWN_PROPERTY_NAMES(input);
    symbols = GET_OWN_PROPERTY_SYMBOLS(input);
    descriptors = GET_OWN_DESCRIPTORS(input);
  } catch {
    throw invalidInvalidationInput();
  }

  const expected = new Set([
    "reviewId",
    "actionId",
    "jobId",
    "invalidatedAt",
    "invalidationReason",
  ]);
  if (
    symbols.length !== 0 ||
    names.length !== expected.size ||
    names.some((name) => !expected.has(name))
  ) {
    throw invalidInvalidationInput();
  }

  const requireData = (key: string): unknown => {
    const read = readField(descriptors, key, GET_OWN_DESCRIPTOR);
    if (read.kind !== "DATA") {
      throw invalidInvalidationInput();
    }
    return read.value;
  };

  const reviewId = requireData("reviewId");
  const actionId = requireData("actionId");
  const jobId = requireData("jobId");
  const invalidatedAt = requireData("invalidatedAt");
  const invalidationReason = requireData("invalidationReason");

  for (const value of [reviewId, actionId, jobId]) {
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      value !== value.trim() ||
      CODE_POINT_REGEX.test(value) ||
      countUnicodeCodePoints(value) > REVIEWER_CODE_POINT_MAX
    ) {
      throw invalidInvalidationInput();
    }
  }
  if (!isCanonicalIsoTimestamp(invalidatedAt as string)) {
    throw invalidInvalidationInput();
  }
  if (
    typeof invalidationReason !== "string" ||
    !INVALIDATION_REASONS.has(invalidationReason as ActionReviewInvalidationReason)
  ) {
    throw invalidInvalidationInput();
  }

  return {
    reviewId: reviewId as string,
    actionId: actionId as string,
    jobId: jobId as string,
    invalidatedAt: invalidatedAt as string,
    invalidationReason: invalidationReason as ActionReviewInvalidationReason,
  };
}

/**
 * Snapshot and validate the deliberately smaller reconciliation insert DTO.
 * The source is fixed to `human`, expiry/invalidation are owned by this
 * primitive, and the review id is generated below.  Keeping this validator
 * descriptor-based makes the primitive safe even when it is reached through
 * a runtime-cast public call rather than the lifecycle's trusted path.
 */
function validateReconciliationInput(input: unknown): ReconciliationReviewInput {
  let names: string[];
  let symbols: symbol[];
  let descriptors: PropertyDescriptorMap;
  try {
    if (input === null || typeof input !== "object" || IS_PROXY(input)) {
      throw invalidReconciliationInput();
    }
    const proto = GET_PROTO(input);
    if (proto !== Object.prototype && proto !== null) {
      throw invalidReconciliationInput();
    }
    names = GET_OWN_PROPERTY_NAMES(input);
    symbols = GET_OWN_PROPERTY_SYMBOLS(input);
    descriptors = GET_OWN_DESCRIPTORS(input);
  } catch {
    throw invalidReconciliationInput();
  }

  const expected = new Set([
    "actionId",
    "jobId",
    "decision",
    "reviewerId",
    "reviewedAt",
    "scopeHash",
    "policyHash",
    "actionHash",
    "contextHash",
    "note",
  ]);
  if (
    symbols.length !== 0 ||
    names.length !== expected.size ||
    names.some((name) => !expected.has(name))
  ) {
    throw invalidReconciliationInput();
  }

  const requireData = (key: string): unknown => {
    const read = readField(descriptors, key, GET_OWN_DESCRIPTOR);
    if (read.kind !== "DATA") throw invalidReconciliationInput();
    return read.value;
  };

  const actionId = requireData("actionId");
  const jobId = requireData("jobId");
  const decision = requireData("decision");
  const reviewerId = requireData("reviewerId");
  const reviewedAt = requireData("reviewedAt");
  const scopeHash = requireData("scopeHash");
  const policyHash = requireData("policyHash");
  const actionHash = requireData("actionHash");
  const contextHash = requireData("contextHash");
  const note = requireData("note");

  for (const value of [actionId, jobId]) {
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      value !== value.trim() ||
      CODE_POINT_REGEX.test(value) ||
      countUnicodeCodePoints(value) > REVIEWER_CODE_POINT_MAX
    ) {
      throw invalidReconciliationInput();
    }
  }
  if (decision !== "executed" && decision !== "failed") {
    throw invalidReconciliationInput();
  }

  // Reconciliation is always a human attestation.  A padded reviewer is
  // accepted at the boundary and persisted canonically trimmed, matching the
  // human approval rule; the policy sentinel is never accepted.
  if (
    typeof reviewerId !== "string" ||
    CODE_POINT_REGEX.test(reviewerId) ||
    reviewerId.trim().length === 0 ||
    reviewerId.trim() === POLICY_REVIEWER_ID ||
    countUnicodeCodePoints(reviewerId.trim()) > REVIEWER_CODE_POINT_MAX
  ) {
    throw invalidReconciliationInput();
  }
  if (!isCanonicalIsoTimestamp(reviewedAt as string)) {
    throw invalidReconciliationInput();
  }
  for (const hash of [scopeHash, policyHash, actionHash, contextHash]) {
    if (!isValidHash(hash)) throw invalidReconciliationInput();
  }
  if (
    typeof note !== "string" ||
    note.trim().length === 0 ||
    countUnicodeCodePoints(note) < 1 ||
    countUnicodeCodePoints(note) > 2_000
  ) {
    throw invalidReconciliationInput();
  }

  return {
    actionId: actionId as string,
    jobId: jobId as string,
    decision: decision as "executed" | "failed",
    reviewerId: (reviewerId as string).trim(),
    reviewedAt: reviewedAt as string,
    scopeHash: scopeHash as string,
    policyHash: policyHash as string,
    actionHash: actionHash as string,
    contextHash: contextHash as string,
    note: note as string,
  };
}

function maskNoteForPersistence(rawNote: string | undefined): string | null {
  if (rawNote === undefined) {
    return null;
  }
  const trimmed = rawNote.trim();
  if (trimmed.length === 0) {
    return null;
  }
  const masked = maskSecrets(trimmed);
  // maskSecrets preserves length; the redacted form may still be empty
  // only if the input was empty after trimming, which we already excluded.
  return masked.length === 0 ? null : masked;
}

/** Defense-in-depth sanitizer for the non-active reconciliation note. */
function sanitizeReconciliationNote(rawNote: string): string {
  let masked = maskSecrets(rawNote).replace(STANDALONE_LOWER_HEX64, "[REDACTED]").trim();
  const output: string[] = [];
  for (const codePoint of Array.from(masked)) {
    const code = codePoint.codePointAt(0) ?? 0;
    output.push(code >= 0xd800 && code <= 0xdfff ? "\ufffd" : codePoint);
    if (output.length >= 2_000) break;
  }
  masked = output.join("");
  if (
    Array.from(masked).length < 1 ||
    masked.replace(/\[REDACTED\]/g, "").trim().length === 0
  ) {
    throw invalidReconciliationInput();
  }
  return masked;
}

function maskNoteForRead(rawNote: string | null | undefined): string | undefined {
  if (rawNote === null || rawNote === undefined) {
    return undefined;
  }
  const masked = maskSecrets(rawNote);
  return masked.length === 0 ? undefined : masked;
}

export class ActionReviewStore {
  constructor(private readonly db: BountyDatabase) {}

  /**
   * Legacy, incomplete audit path. Never a synthetic complete approval.
   * Preserved signatures and ordering; still calls createId/maskSecrets.
   */
  record(input: NewActionReviewInput): ActionReviewRecord {
    const review: ActionReviewRecord = {
      id: createId("review"),
      actionId: input.actionId,
      jobId: input.jobId,
      decision: input.decision,
      note: input.note ? maskSecrets(input.note.trim()) || undefined : undefined,
      createdAt: nowIso(),
    };
    this.db
      .prepare(
        `INSERT INTO action_reviews (
          id, action_id, job_id, decision, note, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(review.id, review.actionId, review.jobId ?? null, review.decision, review.note ?? null, review.createdAt);
    return review;
  }

  /**
   * In-transaction primitive that persists a structurally complete
   * active approval review. Requires an active `withImmediateTransaction`
   * on the EXACT same tracked handle. Never owns, begins, commits, or
   * rolls back a transaction, and never consults
   * `DatabaseSync.isTransaction`.
   *
   * Validation runs before any ID generation or write. Invalid input
   * throws a generic, secret-free BountyPilotError with code
   * ACTION_APPROVAL_INVALID and writes zero rows.
   *
   * The returned record exposes every v2 public field. Invalidation
   * fields are `undefined` on a fresh insert.
   */
  insertApprovalInTransaction(input: CompleteApprovalReviewInput): ActionReviewRecord {
    // 1) Pure guard-state read on the EXACT handle. No SQL, no
    //    DatabaseSync.isTransaction.
    if (!hasImmediateTransaction(this.db)) {
      throw transactionRequired();
    }

    // 2) Runtime structural validation BEFORE createId or any write.
    const validated = validateCompleteApprovalInput(input);

    // 3) Project-generated trusted ID.
    const id = createId("review");
    // 4) createdAt is exactly reviewedAt (no live clock here).
    const createdAt = validated.reviewedAt;
    // 5) Note: trim then mask; empty -> null.
    const persistedNote = maskNoteForPersistence(validated.note);

    // 6) Single in-transaction write. invalidated_at / invalidation_reason
    //    start as NULL on a fresh row.
    this.db
      .prepare(
        `INSERT INTO action_reviews (
          id,
          action_id,
          job_id,
          decision,
          note,
          created_at,
          reviewer_id,
          source,
          reviewed_at,
          expires_at,
          scope_hash,
          policy_hash,
          action_hash,
          context_hash,
          invalidated_at,
          invalidation_reason
        ) VALUES (
          ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?,
          ?, ?, ?, ?,
          ?, ?
        )`,
      )
      .run(
        id,
        validated.actionId,
        validated.jobId,
        validated.decision,
        persistedNote,
        createdAt,
        validated.reviewerId,
        validated.source,
        validated.reviewedAt,
        validated.expiresAt,
        validated.scopeHash,
        validated.policyHash,
        validated.actionHash,
        validated.contextHash,
        null,
        null,
      );

    // 7) Return the full v2 record. Invalidation fields are absent.
    return {
      id,
      actionId: validated.actionId,
      jobId: validated.jobId,
      decision: validated.decision,
      note: persistedNote === null ? undefined : persistedNote,
      createdAt,
      reviewerId: validated.reviewerId,
      source: validated.source,
      reviewedAt: validated.reviewedAt,
      expiresAt: validated.expiresAt,
      scopeHash: validated.scopeHash,
      policyHash: validated.policyHash,
      actionHash: validated.actionHash,
      contextHash: validated.contextHash,
      invalidatedAt: undefined,
      invalidationReason: undefined,
    };
  }

  /**
   * Insert one non-active human reconciliation record.  This primitive is
   * intentionally transaction-bound and never begins/commits/rolls back a
   * transaction itself.  It owns the generated review id and the immutable
   * source/expiry/invalidation projection, so a caller cannot turn a
   * reconciliation attestation into an approval.
   */
  insertReconciliationInTransaction(
    input: ReconciliationReviewInput,
  ): ActionReviewRecord {
    // The exact-handle guard is the first executable operation: a hostile
    // input must not be reflected before the caller proves transaction
    // ownership.
    if (!hasImmediateTransaction(this.db)) {
      throw reconciliationTransactionRequired();
    }

    const validated = validateReconciliationInput(input);
    const persistedNote = sanitizeReconciliationNote(validated.note);
    const id = createId("review");
    const result = this.db
      .prepare(
        `INSERT INTO action_reviews (
          id,
          action_id,
          job_id,
          decision,
          note,
          created_at,
          reviewer_id,
          source,
          reviewed_at,
          expires_at,
          scope_hash,
          policy_hash,
          action_hash,
          context_hash,
          invalidated_at,
          invalidation_reason
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'human', ?, NULL, ?, ?, ?, ?, NULL, NULL)`,
      )
      .run(
        id,
        validated.actionId,
        validated.jobId,
        validated.decision,
        persistedNote,
        validated.reviewedAt,
        validated.reviewerId,
        validated.reviewedAt,
        validated.scopeHash,
        validated.policyHash,
        validated.actionHash,
        validated.contextHash,
      );
    if (result.changes !== 1 && result.changes !== 1n) {
      throw reconciliationWriteInvalid();
    }

    return {
      id,
      actionId: validated.actionId,
      jobId: validated.jobId,
      decision: validated.decision,
      note: persistedNote,
      createdAt: validated.reviewedAt,
      reviewerId: validated.reviewerId,
      source: "human",
      reviewedAt: validated.reviewedAt,
      expiresAt: undefined,
      scopeHash: validated.scopeHash,
      policyHash: validated.policyHash,
      actionHash: validated.actionHash,
      contextHash: validated.contextHash,
      invalidatedAt: undefined,
      invalidationReason: undefined,
    };
  }

  /**
   * Mark one exact linked active approval review invalid inside the caller's
   * tracked immediate transaction. The linkage and both null invalidation
   * predicates are part of the UPDATE so the lifecycle can distinguish the
   * required one-row expiry/drift path from the best-effort current-block
   * repair path without selecting a review note.
   */
  invalidateApprovalInTransaction(
    input: InvalidateApprovalInput,
  ): InvalidateApprovalResult {
    if (!hasImmediateTransaction(this.db)) {
      throw invalidationTransactionRequired();
    }
    const validated = validateInvalidationInput(input);
    const result = this.db
      .prepare(
        `UPDATE action_reviews
         SET invalidated_at = ?, invalidation_reason = ?
         WHERE id = ?
           AND action_id = ?
           AND job_id = ?
           AND invalidated_at IS NULL
           AND invalidation_reason IS NULL`,
      )
      .run(
        validated.invalidatedAt,
        validated.invalidationReason,
        validated.reviewId,
        validated.actionId,
        validated.jobId,
      );
    if (result.changes === 0 || result.changes === 0n) {
      return Object.freeze({ changes: 0 as const });
    }
    if (result.changes === 1 || result.changes === 1n) {
      return Object.freeze({ changes: 1 as const });
    }
    throw invalidInvalidationCount();
  }

  listForAction(actionId: string): ActionReviewRecord[] {
    const rows = this.db
      .prepare("SELECT * FROM action_reviews WHERE action_id = ? ORDER BY created_at ASC")
      .all(actionId) as unknown as ActionReviewRow[];
    return rows.map(rowToReview);
  }

  listForJob(jobId: string): ActionReviewRecord[] {
    const rows = this.db
      .prepare("SELECT * FROM action_reviews WHERE job_id = ? ORDER BY created_at ASC")
      .all(jobId) as unknown as ActionReviewRow[];
    return rows.map(rowToReview);
  }

  list(limit = 100): ActionReviewRecord[] {
    const rows = this.db
      .prepare("SELECT * FROM action_reviews ORDER BY created_at DESC LIMIT ?")
      .all(limit) as unknown as ActionReviewRow[];
    return rows.map(rowToReview);
  }
}

interface ActionReviewRow {
  id: string;
  action_id: string;
  job_id?: string | null;
  decision: ActionReviewDecision;
  note?: string | null;
  created_at: string;
  reviewer_id?: string | null;
  source?: ActionReviewSource | null;
  reviewed_at?: string | null;
  expires_at?: string | null;
  scope_hash?: string | null;
  policy_hash?: string | null;
  action_hash?: string | null;
  context_hash?: string | null;
  invalidated_at?: string | null;
  invalidation_reason?: string | null;
}

function rowToReview(row: ActionReviewRow): ActionReviewRecord {
  return {
    id: row.id,
    actionId: row.action_id,
    jobId: row.job_id ?? undefined,
    decision: row.decision,
    // Re-mask on every read so a row that bypassed write-time masking
    // (e.g. legacy paths, direct SQL) still has secrets stripped on
    // return.
    note: maskNoteForRead(row.note),
    createdAt: row.created_at,
    reviewerId: row.reviewer_id ?? undefined,
    source: row.source ?? undefined,
    reviewedAt: row.reviewed_at ?? undefined,
    expiresAt: row.expires_at ?? undefined,
    scopeHash: row.scope_hash ?? undefined,
    policyHash: row.policy_hash ?? undefined,
    actionHash: row.action_hash ?? undefined,
    contextHash: row.context_hash ?? undefined,
    invalidatedAt: row.invalidated_at ?? undefined,
    invalidationReason: row.invalidation_reason ?? undefined,
  };
}
