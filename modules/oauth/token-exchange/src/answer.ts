import { deepFreeze } from "@mod/kernel";
import type { Tokens } from "@mod/tokens";
import { z } from "zod";
import { accessTokenType, type Exchanged, type ExchangeVerifier } from "./contract.ts";

const strings = z.array(z.string());
/** RFC 6749 §3.3: each scope is one scope-token, so an answer cannot slip in two or an empty one. */
const scopes = z.array(z.string().regex(/^[\x21\x23-\x5b\x5d-\x7e]+$/));
const actor: z.ZodType = z.lazy(() =>
	z.object({ subject: z.string().min(1), actor: actor.optional() }),
);
const shape = z.object({
	subject: z.string().min(1),
	issuer: z.string(),
	issuedTo: z.string().optional(),
	audience: strings,
	scope: scopes,
	expiresAt: z.number(),
	binding: z
		.object({ member: z.string(), confirmation: z.string(), tokenType: z.string() })
		.optional(),
	actor: actor.optional(),
	mayAct: z.array(z.object({ sub: z.string().optional(), iss: z.string().optional() })).optional(),
	amr: strings.optional(),
	authenticatedAt: z.number().optional(),
	acr: z.string().optional(),
	issued: z.string().min(1).optional(),
	kind: z.undefined().optional(),
});
/** An answer is invalid or a token's details, told apart by `kind` alone. */
const answer = z.discriminatedUnion("kind", [z.object({ kind: z.literal("invalid") }), shape]);

/** The verifiers built here, the only ones whose amr, authentication time, acr and `issued` are read. */
const own = new WeakSet<ExchangeVerifier>();

/** Verifies this provider's own access tokens. */
export function selfIssued(tokens: Tokens, issuer: string): ExchangeVerifier {
	const verifier: ExchangeVerifier = {
		tokenType: accessTokenType,
		verify: async (token) => {
			const checked = await tokens.verifyAccess(token);
			if (checked.kind !== "valid") return { kind: "invalid" };
			const { grant } = checked;
			return {
				subject: grant.subject,
				issuer,
				issuedTo: grant.issuedTo,
				audience: grant.audience,
				scope: grant.scope,
				expiresAt: checked.expiresAt,
				issued: checked.id,
				...(checked.binding ? { binding: checked.binding } : {}),
				...(grant.actor ? { actor: grant.actor } : {}),
				...(grant.amr ? { amr: grant.amr } : {}),
				...(grant.authenticatedAt === undefined ? {} : { authenticatedAt: grant.authenticatedAt }),
				...(grant.acr === undefined ? {} : { acr: grant.acr }),
			};
		},
	};
	own.add(verifier);
	return verifier;
}

/** A verifier's answer, its shape checked once and frozen; an invalid or malformed one is no answer. */
export async function verified(
	verifier: ExchangeVerifier,
	token: string,
): Promise<Exchanged | undefined> {
	const parsed = answer.safeParse(await verifier.verify(token));
	if (!parsed.success || parsed.data.kind === "invalid") return undefined;
	const { amr, authenticatedAt, acr, issued, kind: _, ...rest } = parsed.data;
	// Only this provider's own tokens have a family or a session to look up.
	const carried = own.has(verifier)
		? {
				...(amr ? { amr } : {}),
				...(authenticatedAt === undefined ? {} : { authenticatedAt }),
				...(acr === undefined ? {} : { acr }),
				...(issued === undefined ? {} : { issued }),
			}
		: {};
	return deepFreeze({ ...rest, ...carried } as Exchanged);
}
