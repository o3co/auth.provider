/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The one reading of the answer a `DeviceCodeStore`'s `poll`, `approve` or
 * `deny` resolves to: the wrapper around the record, into a plain copy whose
 * fields hold what core's outcome types declare, or a refusal naming the
 * field that does not. A route reads nothing of the store's wrapper but this
 * copy, so a wrapper that is not an object, or a field that throws when read
 * or holds the wrong value, is a refusal it answers rather than an error it
 * lets escape. The record inside stays unread here: it is core's
 * `readDeviceAuthorization`'s.
 */

import type { DeviceDecisionOutcome, DevicePollOutcome } from "@o3co/auth-provider-core";

/** A wrapper `readPollOutcome` or `readDecisionOutcome` refuses. */
export type StoreAnswerRefusal =
	| { readonly ok: false; readonly refused: "outcome_not_an_object" }
	| {
			readonly ok: false;
			readonly refused: "outcome_malformed";
			readonly field: "status" | "intervalSeconds" | "current";
	  };

/** A `poll` answer as read: an approval's record is handed on unread. */
export type PollAnswer =
	| { readonly status: "not_found" | "expired" | "denied" | "pending" }
	| { readonly status: "slow_down"; readonly intervalSeconds: number }
	| { readonly status: "approved"; readonly authorization: unknown };

/** An `approve` or `deny` answer as read: an applied decision's record is handed on unread. */
export type DecisionAnswer =
	| { readonly status: "ok"; readonly authorization: unknown }
	| { readonly status: "not_found" | "expired" }
	| { readonly status: "already_decided"; readonly current: "approved" | "denied" };

/** Every status each outcome type admits: `satisfies` fails the build when the type gains or loses one. */
const POLL_STATUSES = {
	not_found: true,
	expired: true,
	denied: true,
	pending: true,
	slow_down: true,
	approved: true,
} as const satisfies Record<DevicePollOutcome["status"], true>;

const DECISION_STATUSES = {
	ok: true,
	not_found: true,
	expired: true,
	already_decided: true,
} as const satisfies Record<DeviceDecisionOutcome["status"], true>;

const UNREADABLE: unique symbol = Symbol("unreadable");

/** `source[field]`, read once, or `UNREADABLE` for a read that throws. */
const fieldOf = (source: object, field: string): unknown => {
	try {
		return (source as Record<string, unknown>)[field];
	} catch {
		return UNREADABLE;
	}
};

const malformed = (field: "status" | "intervalSeconds" | "current"): StoreAnswerRefusal => ({
	ok: false,
	refused: "outcome_malformed",
	field,
});

const NOT_AN_OBJECT: StoreAnswerRefusal = { ok: false, refused: "outcome_not_an_object" };

/** `outcome`'s `status`, read once, if it is one `statuses` holds. */
const statusOf = <S extends string>(
	outcome: object,
	statuses: Readonly<Record<S, true>>,
): S | undefined => {
	const status = fieldOf(outcome, "status");
	return typeof status === "string" && Object.hasOwn(statuses, status) ? (status as S) : undefined;
};

/**
 * A `poll` answer read once. A `slow_down` interval is held to the rule
 * `readDeviceAuthorization` holds a record's interval to: a finite number of
 * seconds, zero or more.
 */
export function readPollOutcome(
	outcome: unknown,
): { readonly ok: true; readonly answer: PollAnswer } | StoreAnswerRefusal {
	if (typeof outcome !== "object" || outcome === null) return NOT_AN_OBJECT;
	const status = statusOf(outcome, POLL_STATUSES);
	switch (status) {
		case undefined:
			return malformed("status");
		case "slow_down": {
			const intervalSeconds = fieldOf(outcome, "intervalSeconds");
			return typeof intervalSeconds === "number" &&
				Number.isFinite(intervalSeconds) &&
				intervalSeconds >= 0
				? { ok: true, answer: { status, intervalSeconds } }
				: malformed("intervalSeconds");
		}
		case "approved":
			return { ok: true, answer: { status, authorization: fieldOf(outcome, "authorization") } };
		default:
			return { ok: true, answer: { status } };
	}
}

/**
 * An `approve` or `deny` answer read once. An `already_decided` holds a
 * decision: `approved` or `denied`, never `pending`.
 */
export function readDecisionOutcome(
	outcome: unknown,
): { readonly ok: true; readonly answer: DecisionAnswer } | StoreAnswerRefusal {
	if (typeof outcome !== "object" || outcome === null) return NOT_AN_OBJECT;
	const status = statusOf(outcome, DECISION_STATUSES);
	switch (status) {
		case undefined:
			return malformed("status");
		case "already_decided": {
			const current = fieldOf(outcome, "current");
			return current === "approved" || current === "denied"
				? { ok: true, answer: { status, current } }
				: malformed("current");
		}
		case "ok":
			return { ok: true, answer: { status, authorization: fieldOf(outcome, "authorization") } };
		default:
			return { ok: true, answer: { status } };
	}
}
