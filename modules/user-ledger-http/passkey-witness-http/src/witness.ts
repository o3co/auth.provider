import { type LogFields, Unavailable } from "@mod/kernel";
import { witnessWire } from "@mod/ledger-wire";
import { jsonObjectOf, type Narrower, type Outbound, postJson } from "@mod/outbound";
import type { PasskeyWitness } from "@mod/passkey-witness";
import type { z } from "zod";

export interface WitnessParts {
	readonly urls: {
		readonly read: string;
		readonly enroll: string;
		readonly withdraw: string;
	};
	readonly out: Outbound;
	readonly credential: string;
	readonly narrower: Narrower;
	/** How long outbound holds a call made under `narrower`: a write's deadline is its sending time plus this. */
	readonly heldMs: number;
	readonly now: () => number;
	readonly warn: (event: string, fields: LogFields) => void;
}

type Call = "read" | "enroll" | "withdraw";

/** The passkey witness kept at the operator's ledger: every call asks it, nothing is kept here. */
export function witnessAt(parts: WitnessParts): PasskeyWitness {
	const { urls, out, credential, narrower, heldMs, now, warn } = parts;
	/** Logs why the ledger failed, by the call and its kind or status alone, and answers unavailable. */
	const failed = (call: Call, why: { reason: string } | { status: number }) => {
		warn("passkey-witness-http.ledger_failed", { call, ...why });
		return new Unavailable("passkey-witness-http");
	};
	const post = (call: Call, body: Record<string, unknown>) =>
		postJson(out, { url: urls[call], body, credential, narrower }, (reason) =>
			failed(call, { reason }),
		);
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
	const mark = (subject: string) =>
		answered("read", witnessWire.read(subject), witnessWire.markAnswer);
	return {
		read: async (subject) => (await mark(subject)).enrolled,
		markedWith: async (subject) => {
			const read = await mark(subject);
			return read.enrolled ? read.token : undefined;
		},
		enroll: async (subject, token) =>
			(
				await answered(
					"enroll",
					witnessWire.enroll(subject, token, deadline()),
					witnessWire.enrollAnswer,
				)
			).owner,
		// 204 only once the ledger has judged the token and removed what it had to: anything else is unavailable.
		withdraw: async (subject, token) => {
			const answer = await post("withdraw", witnessWire.withdraw(subject, token, deadline()));
			if (answer.status !== witnessWire.written)
				throw failed("withdraw", { status: answer.status });
		},
	};
}
