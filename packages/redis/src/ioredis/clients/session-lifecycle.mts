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
 * The session lifecycle store's client over one ioredis connection. Every
 * write and every index step is one script whose reply is held to its
 * declared answers; a reply of any other shape throws, as a script this
 * client did not run.
 */

import type { Redis } from "ioredis";
import type {
	SessionClosingPage,
	SessionLifecycleCompleteReply,
	SessionLifecycleStoreClient,
} from "../../clients.mjs";
import { runScript } from "../commands.mjs";
import { redisDurability } from "../durability.mjs";
import {
	LC_BEGIN_CLOSE,
	LC_COMPLETE,
	LC_INDEX_ADD,
	LC_INDEX_PAGE,
	LC_INDEX_PRUNE_IF,
	LC_INDEX_PRUNE_OUTLIVED,
	LC_JOIN,
	LC_OPEN,
} from "../scripts/session-lifecycle.mjs";

const unexpected = (operation: string): Error =>
	new Error(`sessionLifecycleStoreClient.${operation}: unexpected reply`);

/** `reply` when it is one of `answers`; anything else is a script this client did not run. */
const answerOf = <const A extends string>(
	reply: unknown,
	answers: readonly A[],
	operation: string,
): A => {
	if ((answers as readonly unknown[]).includes(reply)) return reply as A;
	throw unexpected(operation);
};

/** A flat `[field, value, …]` reply of strings as an object; anything else throws. */
const fieldsOf = (reply: unknown, operation: string): Record<string, string> => {
	if (!Array.isArray(reply) || reply.length % 2 !== 0) throw unexpected(operation);
	const fields: Record<string, string> = Object.create(null);
	for (let i = 0; i < reply.length; i += 2) {
		const [field, value] = [reply[i], reply[i + 1]];
		if (typeof field !== "string" || typeof value !== "string") throw unexpected(operation);
		fields[field] = value;
	}
	return fields;
};

const DECIMAL = /^(0|[1-9]\d*)$/;

/** A completion's reply: `closed:<until>` read into its parts. */
const completeReplyOf = (reply: unknown): SessionLifecycleCompleteReply => {
	if (typeof reply === "string" && reply.startsWith("closed:")) {
		const until = reply.slice("closed:".length);
		if (!DECIMAL.test(until) || !Number.isSafeInteger(Number(until))) {
			throw unexpected("completeRecordItem");
		}
		return { outcome: "closed", retainUntilMs: Number(until) };
	}
	return {
		outcome: answerOf(
			reply,
			["updated", "missing", "conflict", "not_pending", "late"] as const,
			"completeRecordItem",
		),
	};
};

/** A page's reply: the clock, then sid and deadline pairs. */
const pageOf = (reply: unknown): SessionClosingPage => {
	if (!Array.isArray(reply) || reply.length % 2 !== 1) throw unexpected("closingPage");
	const [now, ...rest] = reply as unknown[];
	if (typeof now !== "string" || !DECIMAL.test(now)) throw unexpected("closingPage");
	const entries: { sid: string; deadline: string }[] = [];
	for (let i = 0; i < rest.length; i += 2) {
		const [sid, deadline] = [rest[i], rest[i + 1]];
		if (typeof sid !== "string" || typeof deadline !== "string") throw unexpected("closingPage");
		entries.push({ sid, deadline });
	}
	return { nowMs: Number(now), entries };
};

export function makeIoredisSessionLifecycleStoreClient(io: Redis): SessionLifecycleStoreClient {
	return {
		openRecord: async (key, input) =>
			answerOf(
				await runScript(
					io,
					LC_OPEN,
					[key, input.replayKey],
					[
						String(input.deadlineMs),
						String(input.deadlineMs + input.clockSkewMs + 1),
						input.sub,
						String(input.expiresAtMs),
						String(input.retainUntilMs),
						input.generation,
					],
				),
				["opened", "refused", "late"] as const,
				"openRecord",
			),
		joinRecord: async (key, input) =>
			answerOf(
				await runScript(
					io,
					LC_JOIN,
					[key, input.replayKey],
					[
						String(input.deadlineMs),
						String(input.deadlineMs + input.clockSkewMs + 1),
						input.item,
						input.data,
						input.generation,
						String(input.maxParticipants),
					],
				),
				["joined", "closed", "missing", "full", "late"] as const,
				"joinRecord",
			),
		beginCloseRecord: async (key, input) => {
			const reply = await runScript(
				io,
				LC_BEGIN_CLOSE,
				[key],
				[
					String(input.deadlineMs),
					input.generation,
					input.cause,
					String(input.retainMs),
					input.steps.join(","),
					input.perParticipant.join(","),
				],
			);
			if (reply === "missing" || reply === "late") return reply;
			return fieldsOf(reply, "beginCloseRecord");
		},
		completeRecordItem: async (key, input) =>
			completeReplyOf(
				await runScript(
					io,
					LC_COMPLETE,
					[key, input.replayKey],
					[
						String(input.deadlineMs),
						String(input.deadlineMs + input.clockSkewMs + 1),
						input.expected,
						input.item,
						input.generation,
					],
				),
			),
		readRecord: async (key) => {
			const fields = await io.hgetall(key);
			return Object.keys(fields).length === 0 ? null : fields;
		},
		recordState: (key) => io.hget(key, "state"),
		addClosing: async (index, sid, deadlineMs) =>
			answerOf(
				await runScript(io, LC_INDEX_ADD, [index.sids, index.deadlines], [sid, String(deadlineMs)]),
				["added", "late"] as const,
				"addClosing",
			),
		closingPage: async (index, after, count) =>
			pageOf(
				await runScript(
					io,
					LC_INDEX_PAGE,
					[index.sids, index.deadlines],
					[after === "" ? "-" : `(${after}`, String(count)],
				),
			),
		pruneClosingIf: async (index, sid, deadline) =>
			(await runScript(io, LC_INDEX_PRUNE_IF, [index.sids, index.deadlines], [sid, deadline])) ===
			1,
		pruneClosingOutlived: async (index, sid, retainUntilMs, clockSkewMs) =>
			(await runScript(
				io,
				LC_INDEX_PRUNE_OUTLIVED,
				[index.sids, index.deadlines],
				[sid, String(retainUntilMs), String(clockSkewMs)],
			)) === 1,
		durability: () => redisDurability(io),
	};
}
