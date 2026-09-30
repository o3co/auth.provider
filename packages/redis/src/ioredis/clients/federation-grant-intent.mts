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
 * The federation grant intent store's client: five operations one script each, and two plain
 * reads. A reply a script does not document throws rather than reading as an answer.
 */

import type { Redis } from "ioredis";
import type {
	FederationGrantConsentAnswered,
	FederationGrantIntentAdmission,
	FederationGrantIntentStoreClient,
} from "../../clients.mjs";
import { fgiText, fgNumber } from "../codec.mjs";
import { runScript } from "../commands.mjs";
import {
	FGI_ADMIT,
	FGI_ANSWER,
	FGI_CONSUME,
	FGI_FINISH,
	FGI_PARK,
} from "../scripts/federation-grant-intent.mjs";

/** What the intent scripts need of a connection: the script calls, and nothing else. */
export interface FederationGrantIntentRedisCommands {
	evalsha(sha: string, numkeys: number, ...args: (string | number)[]): Promise<unknown>;
	eval(script: string, numkeys: number, ...args: (string | number)[]): Promise<unknown>;
	hmget(key: string, ...fields: string[]): Promise<(string | null)[]>;
	exists(key: string): Promise<number>;
}

/**
 * The two reads are plain commands, not scripts: nothing is written, so
 * nothing needs to be one step with anything else. Whatever a read concludes,
 * the write that follows it — parking, answering — checks again inside its own
 * script, so a read that raced a write can only make a caller give up early,
 * never let one through.
 */
const fgiLiveUntil = (fields: readonly (string | null)[], nowMs: number): boolean => {
	const expiresAt = Number(fields[0]);
	return Number.isFinite(expiresAt) && nowMs < expiresAt;
};

const ADMISSION_REFUSALS = new Set(["limit", "collision", "closed", "expired"]);

/**
 * The federation grant intent store's connection. It may be the grant store's own: nothing
 * here needs a second one, and the keys live under a different hash tag either way.
 */
export function makeIoredisFederationGrantIntentStoreClient(
	io: FederationGrantIntentRedisCommands,
): FederationGrantIntentStoreClient {
	const connection = io as unknown as Redis;
	return {
		async admitIntent(prefix, input): Promise<FederationGrantIntentAdmission> {
			const reply = await runScript(
				connection,
				FGI_ADMIT,
				[`${prefix}i:${input.handle}`],
				[
					prefix,
					input.handle,
					input.record,
					fgNumber(input.expiresAtMs),
					fgNumber(input.nowMs),
					input.pair,
					input.counts ? "1" : "0",
					fgNumber(input.limit),
					fgNumber(input.reservationAllowanceMs),
				],
			);
			const outcome = Array.isArray(reply) ? reply[0] : undefined;
			if (outcome === "created" || outcome === "unchanged") return { outcome };
			const reason = Array.isArray(reply) ? reply[1] : undefined;
			if (outcome === "refused" && typeof reason === "string" && ADMISSION_REFUSALS.has(reason)) {
				return {
					outcome: "refused",
					reason: reason as FederationGrantIntentAdmission["reason"] & string,
				};
			}
			// A reply this release does not know is not an admission: say so rather
			// than let a record the caller believes it wrote go unwritten silently.
			throw new Error(
				"federation grant intent store: the admission script answered nothing it knows",
			);
		},

		async readIntent(prefix, handle, nowMs) {
			const fields = await io.hmget(`${prefix}i:${handle}`, "expiresAt", "closed", "record");
			if (fields[1] === "1" || !fgiLiveUntil(fields, nowMs)) return null;
			return fields[2] ?? null;
		},

		async parkConsent(prefix, input) {
			return fgiText(
				await runScript(
					connection,
					FGI_PARK,
					[`${prefix}i:${input.handle}`],
					[
						prefix,
						input.handle,
						input.challenge,
						input.record,
						input.binding,
						fgNumber(input.expiresAtMs),
						fgNumber(input.nowMs),
					],
				),
			);
		},

		async readConsent(prefix, challenge, nowMs) {
			const fields = await io.hmget(`${prefix}c:${challenge}`, "expiresAt", "intent", "record");
			if (!fgiLiveUntil(fields, nowMs) || fields[1] === null || fields[1] === undefined)
				return null;
			// While its intent is still there: a consent outliving a reclaimed intent
			// answers nothing, whichever key Redis happened to drop first.
			if ((await io.exists(`${prefix}i:${fields[1]}`)) === 0) return null;
			return fields[2] ?? null;
		},

		async answerConsent(prefix, input): Promise<FederationGrantConsentAnswered> {
			const reply = await runScript(
				connection,
				FGI_ANSWER,
				[`${prefix}c:${input.challenge}`],
				[
					prefix,
					fgNumber(input.nowMs),
					input.binding,
					input.decision,
					input.state ?? "",
					input.transaction ?? "",
					fgNumber(input.transactionExpiresAtMs ?? 0),
					input.connection ?? "",
				],
			);
			const outcome = Array.isArray(reply) ? reply[0] : undefined;
			const record = Array.isArray(reply) && typeof reply[1] === "string" ? reply[1] : undefined;
			if (outcome === "denied" || outcome === "accepted") {
				return record === undefined ? { outcome } : { outcome, record };
			}
			if (outcome === "state_collision" || outcome === "empty") return { outcome };
			throw new Error("federation grant intent store: the answer script answered nothing it knows");
		},

		async consumeTransaction(prefix, input) {
			return fgiText(
				await runScript(
					connection,
					FGI_CONSUME,
					[`${prefix}tx:${input.state}`],
					[prefix, input.connection, fgNumber(input.nowMs)],
				),
			);
		},

		async finishIntent(prefix, handle, _nowMs) {
			await runScript(connection, FGI_FINISH, [`${prefix}i:${handle}`], [prefix, handle]);
		},
	};
}
