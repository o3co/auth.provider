import { deepFreeze } from "@mod/kernel";
import type { Tokens } from "@mod/tokens";
import { z } from "zod";
import {
	accessTokenType,
	type Exchanged,
	type ExchangeVerifier,
	type ForeignToken,
	type OwnToken,
} from "./contract.ts";

const strings = z.array(z.string());
/** RFC 6749 §3.3: each scope is one scope-token, so an answer cannot slip in two or an empty one. */
const scopes = z.array(z.string().regex(/^[\x21\x23-\x5b\x5d-\x7e]+$/));
const actor: z.ZodType = z.lazy(() =>
	z.object({ subject: z.string().min(1), actor: actor.optional() }),
);
const common = {
	subject: z.string().min(1),
	issuer: z.string(),
	expiresAt: z.number(),
	// None, or one not a finite number, stands before any boundary.
	standingAt: z.number().catch(0),
};
const ownFields = {
	issuedTo: z.string().optional(),
	audience: strings,
	scope: scopes,
	binding: z
		.object({ member: z.string(), confirmation: z.string(), tokenType: z.string() })
		.optional(),
	actor: actor.optional(),
	mayAct: z.array(z.object({ sub: z.string().optional(), iss: z.string().optional() })).optional(),
	amr: strings.optional(),
	authenticatedAt: z.number().optional(),
	acr: z.string().optional(),
	issued: z.string().min(1).optional(),
};
const clients = z.array(z.string().min(1)).min(1);
const holderDigest = z
	.string()
	.regex(/^[A-Za-z0-9_-]{43}$/)
	.optional();
const own = z.object({ kind: z.literal("own"), ...common, ...ownFields });
const foreign = z.object({ kind: z.literal("foreign"), ...common, clients, holderDigest });
/** An answer is invalid or a token's details, told apart by `kind` alone. */
const answer = z.discriminatedUnion("kind", [
	z.object({ kind: z.literal("invalid") }),
	own,
	foreign,
]);

/** A foreign token as its answer says it, a holder digest only where one is given. */
const foreignOf = (read: {
	subject: string;
	issuer: string;
	expiresAt: number;
	standingAt: number;
	clients: string[];
	holderDigest?: string | undefined;
}): ForeignToken & Read => ({
	kind: "foreign",
	subject: read.subject,
	issuer: read.issuer,
	expiresAt: read.expiresAt,
	standingAt: read.standingAt,
	clients: read.clients as [string, ...string[]],
	...(read.holderDigest === undefined ? {} : { holderDigest: read.holderDigest }),
});

/** The verifiers built here, the only ones whose amr, authentication time, acr and `issued` are read. */
const built = new WeakSet<ExchangeVerifier>();

/** Verifies this provider's own access tokens. */
export function selfIssued(tokens: Tokens, issuer: string): ExchangeVerifier {
	const verifier: ExchangeVerifier = {
		tokenType: accessTokenType,
		verify: async (token) => {
			const checked = await tokens.verifyAccess(token);
			if (checked.kind !== "valid") return { kind: "invalid" };
			const { grant } = checked;
			return {
				kind: "own",
				subject: grant.subject,
				issuer,
				issuedTo: grant.issuedTo,
				audience: grant.audience,
				scope: grant.scope,
				expiresAt: checked.expiresAt,
				standingAt: checked.standingAt,
				issued: checked.id,
				...(checked.binding ? { binding: checked.binding } : {}),
				...(grant.actor ? { actor: grant.actor } : {}),
				...(grant.amr ? { amr: grant.amr } : {}),
				...(grant.authenticatedAt === undefined ? {} : { authenticatedAt: grant.authenticatedAt }),
				...(grant.acr === undefined ? {} : { acr: grant.acr }),
			};
		},
	};
	built.add(verifier);
	return verifier;
}

/** A verifier's answer as read, its standing time always given. */
export type Read = Exchanged & { readonly standingAt: number };

/** A verifier's answer, its shape checked once and frozen; an invalid or malformed one is no answer. */
export async function verified(
	verifier: ExchangeVerifier,
	token: string,
): Promise<Read | undefined> {
	const parsed = answer.safeParse(await verifier.verify(token));
	if (!parsed.success || parsed.data.kind === "invalid") return undefined;
	const read: Read =
		parsed.data.kind === "foreign" ? foreignOf(parsed.data) : (parsed.data as OwnToken & Read);
	if (read.kind === "foreign") return deepFreeze(read);
	const { amr, authenticatedAt, acr, issued, ...rest } = read;
	// Only this provider's own tokens have a family or a session to look up.
	const carried = built.has(verifier)
		? {
				...(amr ? { amr } : {}),
				...(authenticatedAt === undefined ? {} : { authenticatedAt }),
				...(acr === undefined ? {} : { acr }),
				...(issued === undefined ? {} : { issued }),
			}
		: {};
	return deepFreeze({ ...rest, ...carried });
}
