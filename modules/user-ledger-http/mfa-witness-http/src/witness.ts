import { type LogFields, Unavailable } from "@mod/kernel";
import { witnessWire } from "@mod/ledger-wire";
import type { EnrollmentWitness } from "@mod/mfa-witness";
import { jsonObjectOf, type Narrower, type Outbound, postJson } from "@mod/outbound";
import type { z } from "zod";

export interface WitnessParts {
	readonly urls: {
		readonly read: string;
		readonly enroll: string;
		readonly clear: string;
		/** None leaves withdraw and markedWith out: the ledger has no route for it, and its read need name no token. */
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

/** The enrollment witness kept at the operator's ledger: every call asks it, nothing is kept here. */
export function witnessAt(parts: WitnessParts): EnrollmentWitness {
	const { urls, out, credential, narrower, heldMs, now, warn } = parts;
	/** Logs why the ledger failed, by the call and its kind or status alone, and answers unavailable. */
	const failed = (call: Call, why: { reason: string } | { status: number }) => {
		warn("mfa-witness-http.ledger_failed", { call, ...why });
		return new Unavailable("mfa-witness-http");
	};
	const post = (call: Call, url: string, body: Record<string, unknown>) =>
		postJson(out, { url, body, credential, narrower }, (reason) => failed(call, { reason }));
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
		if (answer.status !== witnessWire.written) throw failed(call, { status: answer.status });
	};
	const withdrawUrl = urls.withdraw;
	// Where withdraw is offered, a marked answer names its mark's token.
	const mark = (subject: string) =>
		answered("read", witnessWire.read(subject), witnessWire.markAnswer);
	const witness: EnrollmentWitness = {
		read: async (subject) =>
			withdrawUrl === undefined
				? (await answered("read", witnessWire.read(subject), witnessWire.readAnswer)).enrolled
				: (await mark(subject)).enrolled,
		enroll: async (subject, token) =>
			(
				await answered(
					"enroll",
					witnessWire.enroll(subject, token, deadline()),
					witnessWire.enrollAnswer,
				)
			).owner,
		clear: (subject) => written("clear", urls.clear, witnessWire.clear(subject, deadline())),
	};
	// Left out, not undefined, where the ledger has no route for it.
	if (withdrawUrl !== undefined) {
		witness.withdraw = (subject, token) =>
			written("withdraw", withdrawUrl, witnessWire.withdraw(subject, token, deadline()));
		witness.markedWith = async (subject) => {
			const read = await mark(subject);
			return read.enrolled ? read.token : undefined;
		};
	}
	return witness;
}
