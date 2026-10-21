import { deepFreeze, type LogFields, Unavailable } from "@mod/kernel";
import type { EnrollmentWitness } from "@mod/mfa-witness";
import {
	DestinationRefused,
	isOutboundUnavailable,
	jsonObjectOf,
	type Narrower,
	type Outbound,
} from "@mod/outbound";
import { z } from "zod";

export interface WitnessParts {
	readonly urls: {
		readonly read: string;
		readonly enroll: string;
		readonly clear: string;
		/** None leaves withdraw out: the ledger has no route for it. */
		readonly withdraw?: string | undefined;
	};
	readonly out: Outbound;
	readonly credential: string;
	readonly narrower: Narrower;
	/** How long outbound holds a call made under `narrower`: a write's deadline is its sending time plus this. */
	readonly heldMs: number;
	readonly now: () => number;
	readonly warn: (event: string, fields: LogFields) => void;
}

type Call = "read" | "enroll" | "clear" | "withdraw";

const readShape = z.object({ enrolled: z.boolean() });
const enrollShape = z.object({ owner: z.boolean() });

/** The kind outbound gives a failure to send, or no-answer for anything else. */
function kindOf(error: unknown): string {
	if (DestinationRefused.is(error)) return error.reason;
	if (isOutboundUnavailable(error)) return error.failure;
	return "no-answer";
}

/** The enrollment witness kept at the operator's ledger: every call asks it, nothing is kept here. */
export function witnessAt(parts: WitnessParts): EnrollmentWitness {
	const { urls, out, credential, narrower, heldMs, now, warn } = parts;
	/** Logs why the ledger failed, by the call and its kind or status alone, and answers unavailable. */
	const failed = (call: Call, why: { reason: string } | { status: number }) => {
		warn("mfa-witness-http.ledger_failed", { call, ...why });
		return new Unavailable("mfa-witness-http");
	};
	const headers = deepFreeze({ accept: "application/json", "content-type": "application/json" });
	const post = (call: Call, url: string, body: Record<string, unknown>) =>
		out
			.fetch(
				url,
				{ method: "POST", headers, body: JSON.stringify(body), credential: `Bearer ${credential}` },
				narrower,
			)
			.catch((error: unknown) => {
				throw failed(call, { reason: kindOf(error) });
			});
	/** The one JSON object a 200 holds, in the shape asked; any other answer is unavailable. */
	const answered = async <T>(
		call: "read" | "enroll",
		body: Record<string, unknown>,
		shape: z.ZodType<T>,
	) => {
		const read = jsonObjectOf(await post(call, urls[call], body));
		if (read.kind === "other") throw failed(call, { status: read.status });
		const parsed = shape.safeParse(read.value);
		if (!parsed.success) throw failed(call, { reason: "malformed" });
		return parsed.data;
	};
	// A write the ledger receives past its deadline is one the provider no longer waits for.
	const deadline = () => now() + heldMs;
	/** A write the ledger answers 204 once done; any other answer is unavailable, never another call. */
	const written = async (
		call: "clear" | "withdraw",
		url: string,
		body: Record<string, unknown>,
	) => {
		const answer = await post(call, url, body);
		if (answer.status !== 204) throw failed(call, { status: answer.status });
	};
	const witness: EnrollmentWitness = {
		read: async (subject) => (await answered("read", { subject }, readShape)).enrolled,
		enroll: async (subject, token) =>
			(await answered("enroll", { subject, token, deadline: deadline() }, enrollShape)).owner,
		clear: (subject) => written("clear", urls.clear, { subject, deadline: deadline() }),
	};
	// Left out, not undefined, where the ledger has no route for it.
	const withdrawUrl = urls.withdraw;
	if (withdrawUrl !== undefined) {
		witness.withdraw = (subject, token) =>
			written("withdraw", withdrawUrl, { subject, token, deadline: deadline() });
	}
	return witness;
}
