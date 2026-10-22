import { deepFreeze, type LogFields, Unavailable } from "@mod/kernel";
import {
	DestinationRefused,
	isOutboundUnavailable,
	jsonObjectOf,
	type Narrower,
	type Outbound,
} from "@mod/outbound";
import type { PasskeyWitness } from "@mod/passkeys";
import { z } from "zod";

export interface WitnessParts {
	readonly urls: {
		readonly read: string;
		readonly enroll: string;
		readonly withdraw: string;
		readonly clear: string;
	};
	readonly out: Outbound;
	readonly credential: string;
	readonly narrower: Narrower;
	/** How long outbound holds a call made under `narrower`: a write's deadline is its sending time plus this. */
	readonly heldMs: number;
	readonly now: () => number;
	readonly warn: (event: string, fields: LogFields) => void;
}

type Call = "read" | "enroll" | "withdraw" | "clear";

/**
 * A path or query with what RFC 3986 calls equivalent spelled one way: an unreserved character
 * encoded is the character, and the hex of any other encoding upper case (§6.2.2.1, §6.2.2.2).
 */
const equivalent = (part: string) =>
	part.replace(/%([0-9A-Fa-f]{2})/g, (_, hex: string) => {
		const char = String.fromCharCode(Number.parseInt(hex, 16));
		return /[A-Za-z0-9\-._~]/.test(char) ? char : `%${hex.toUpperCase()}`;
	});

/** Whether two URLs reach one target as outbound sends them: their origin, path and query, whatever their spelling. */
export function sameTarget(a: string, b: string): boolean {
	const [x, y] = [new URL(a), new URL(b)];
	return (
		x.origin === y.origin &&
		equivalent(x.pathname) === equivalent(y.pathname) &&
		equivalent(x.search) === equivalent(y.search)
	);
}

const readShape = z.object({ enrolled: z.boolean() });
const enrollShape = z.object({ owner: z.boolean() });

/** The kind outbound gives a failure to send, or no-answer for anything else. */
function kindOf(error: unknown): string {
	if (DestinationRefused.is(error)) return error.reason;
	if (isOutboundUnavailable(error)) return error.failure;
	return "no-answer";
}

/** The passkey witness kept at the operator's ledger: every call asks it, nothing is kept here. */
export function witnessAt(parts: WitnessParts): PasskeyWitness {
	const { urls, out, credential, narrower, heldMs, now, warn } = parts;
	/** Logs why the ledger failed, by the call and its kind or status alone, and answers unavailable. */
	const failed = (call: Call, why: { reason: string } | { status: number }) => {
		warn("passkey-witness-http.ledger_failed", { call, ...why });
		return new Unavailable("passkey-witness-http");
	};
	const headers = deepFreeze({ accept: "application/json", "content-type": "application/json" });
	const post = (call: Call, body: Record<string, unknown>) =>
		out
			.fetch(
				urls[call],
				{ method: "POST", headers, body: JSON.stringify(body), credential: `Bearer ${credential}` },
				narrower,
			)
			.catch((error: unknown) => {
				throw failed(call, { reason: kindOf(error) });
			});
	/** The one JSON object a 200 holds, in the shape asked; any other answer is unavailable. */
	const answered = async <T>(call: Call, body: Record<string, unknown>, shape: z.ZodType<T>) => {
		const read = jsonObjectOf(await post(call, body));
		if (read.kind === "other") throw failed(call, { status: read.status });
		const parsed = shape.safeParse(read.value);
		if (!parsed.success) throw failed(call, { reason: "malformed" });
		return parsed.data;
	};
	// A write the ledger receives past its deadline is one the provider no longer waits for.
	const deadline = () => now() + heldMs;
	return {
		read: async (subject) => (await answered("read", { subject }, readShape)).enrolled,
		enroll: async (subject, token) =>
			(await answered("enroll", { subject, token, deadline: deadline() }, enrollShape)).owner,
		// 204 only once the ledger has judged the token and removed what it had to: anything else is unavailable.
		withdraw: async (subject, token) => {
			const answer = await post("withdraw", { subject, token, deadline: deadline() });
			if (answer.status !== 204) throw failed("withdraw", { status: answer.status });
		},
		clear: async (subject) => {
			const answer = await post("clear", { subject, deadline: deadline() });
			if (answer.status !== 204) throw failed("clear", { status: answer.status });
		},
	};
}
