import { algorithms, type SignerKeys } from "@mod/jwt-bearer";
import { deepFreeze, type LogFields, Unavailable } from "@mod/kernel";
import {
	DestinationRefused,
	jsonObjectOf,
	type Narrower,
	type Outbound,
	OutboundUnavailable,
} from "@mod/outbound";
import { z } from "zod";

export interface LookupParts {
	readonly issuer: string;
	readonly url: string;
	readonly out: Outbound;
	readonly credential: string | undefined;
	readonly narrower: Narrower;
	readonly warn: (event: string, fields: LogFields) => void;
}

/** A JWK's members that hold private key material: a key carrying any is never handed on. */
const privateMembers = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

const answerShape = z.object({
	keys: z.array(z.record(z.string(), z.unknown())),
	algorithms: z.array(z.enum(algorithms)).min(1).optional(),
});

/** The kind outbound gives a failure to send, or no-answer for anything else. */
function kindOf(error: unknown): string {
	if (error instanceof DestinationRefused) return error.reason;
	if (error instanceof OutboundUnavailable) return error.failure;
	return "no-answer";
}

/** The signer keys of one issuer, asked of the ledger on every assertion, never kept. */
export function keysAt(parts: LookupParts): SignerKeys {
	const { issuer, url, out, credential, narrower, warn } = parts;
	/** Logs why the ledger failed, by its kind or status alone, and answers unavailable. */
	const failed = (why: { reason: string } | { status: number }) => {
		warn("signer-keys-http.ledger_failed", why);
		return new Unavailable("signer-keys-http");
	};
	const headers = deepFreeze({
		accept: "application/json",
		"content-type": "application/json",
		...(credential === undefined ? {} : { authorization: `Bearer ${credential}` }),
	});
	return {
		issuer,
		async keysOf({ subject, kid }) {
			// A kid the assertion does not name is left out, as JSON writes no undefined member.
			const body = JSON.stringify({ issuer, subject, kid });
			const answer = await out
				.fetch(url, { method: "POST", headers, body }, narrower)
				.catch((error: unknown) => {
					throw failed({ reason: kindOf(error) });
				});
			// Not known, or known and revoked: both are no keys here.
			if (answer.status === 404 || answer.status === 410) return { kind: "none" };
			if (answer.status !== 200) throw failed({ status: answer.status });
			const read = jsonObjectOf(answer);
			const parsed = read.kind === "object" ? answerShape.safeParse(read.value) : undefined;
			// The ledger says the signer holds no key now.
			if (parsed?.success && parsed.data.keys.length === 0) return { kind: "none" };
			const keys = parsed?.success
				? parsed.data.keys.filter((jwk) => !privateMembers.some((m) => Object.hasOwn(jwk, m)))
				: [];
			if (!parsed?.success || keys.length === 0) throw failed({ reason: "malformed" });
			return deepFreeze({
				kind: "keys",
				keys,
				algorithms: parsed.data.algorithms ?? [...algorithms],
			});
		},
	};
}
