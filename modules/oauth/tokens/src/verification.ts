import { type AddedClaims, addedClaimsIn, addedClaimsOf } from "@mod/added-claims";
import type { AccessTokenSigning } from "@mod/keys";
import type { SenderBindings } from "@mod/sender-binding";
import { z } from "zod";
import type { AccessCheck, AccessGrant, Actor } from "./contract.ts";
import { chainWithin, issuedWithin } from "./limits.ts";
import { standingRead } from "./standing/standing.ts";

/** An actor chain as an access token's `act` writes it. */
export interface Act {
	readonly sub: string;
	readonly act?: Act | undefined;
}
const actShape: z.ZodType<Act> = z.lazy(() =>
	z.object({ sub: z.string(), act: actShape.optional() }),
);

const actorOf = (act: Act): Actor =>
	Object.freeze({ subject: act.sub, ...(act.act ? { actor: actorOf(act.act) } : {}) });

const claimsShape = z.object({
	iss: z.string(),
	sub: z.string(),
	aud: z.union([z.string(), z.array(z.string())]),
	client_id: z.string(),
	scope: z.string().optional(),
	exp: z.number(),
	iat: z.number(),
	jti: z.string().min(1),
	cnf: z.record(z.string(), z.string()).optional(),
	act: actShape.optional(),
	amr: z.array(z.string()).optional(),
	auth_time: z.number().optional(),
	acr: z.string().min(1).optional(),
	// Whole seconds; a value present in another shape is no token of tokens', never an absent one.
	o3co_standing_at: z.number().int().optional(),
});

type Claims = z.infer<typeof claimsShape>;

/** The longest compact access token tokens issues or reads, so it always takes what it issued. */
export const compactLimit = 16_384;
/** Whether a payload's actor chain is within the depth tokens issues. */
const actorsWithin = (act: unknown) => chainWithin(act, (link) => (link as { act?: unknown }).act);
type Valid = Extract<AccessCheck, { kind: "valid" }>;
type Invalid = Extract<AccessCheck, { kind: "invalid" }>;
type Checked =
	| { readonly kind: "checked"; readonly access: Valid; readonly issuedAt: number }
	| Invalid;

/** The grant read back from verified claims, and the claims its grant added. */
const grantOf = (claims: Claims, added: AddedClaims | undefined): AccessGrant =>
	Object.freeze({
		subject: claims.sub,
		issuedTo: claims.client_id,
		audience: Object.freeze(typeof claims.aud === "string" ? [claims.aud] : claims.aud),
		scope: Object.freeze(claims.scope ? claims.scope.split(" ") : []),
		...(claims.act ? { actor: actorOf(claims.act) } : {}),
		...(claims.amr ? { amr: Object.freeze(claims.amr) } : {}),
		...(claims.auth_time === undefined ? {} : { authenticatedAt: claims.auth_time * 1000 }),
		...(claims.acr === undefined ? {} : { acr: claims.acr }),
		...(added ? { claims: added } : {}),
	});

/** The added claims of a verified payload, copied as an issue copies them; undefined for a token none of tokens' issued. */
const addedOf = (payload: Readonly<Record<string, unknown>>) => {
	try {
		return { added: addedClaimsOf(addedClaimsIn(payload)) };
	} catch (error) {
		if (error instanceof TypeError) return undefined;
		throw error;
	}
};

export interface CheckingParts {
	readonly signing: Pick<AccessTokenSigning, "verify">;
	readonly bindings: Pick<SenderBindings, "tokenTypeOf">;
	/** The issuer a token must name. */
	readonly iss: string;
	readonly now: () => number;
}

/** Verifies everything but revocation; `allowanceMs` keeps a just-expired token valid. */
export function checkingWith({ signing, bindings, iss, now }: CheckingParts) {
	return async (token: string, allowanceMs = 0): Promise<Checked> => {
		if (token.length > compactLimit) return { kind: "invalid", reason: "shape" };
		const verified = await signing.verify(token);
		if (verified.kind === "invalid") return { kind: "invalid", reason: "signature" };
		// Taken from the payload as signed, before the shape drops what it does not name: a member
		// reserved and never written, or one outside the rules, is no token of tokens'.
		const extra = addedOf(verified.claims);
		if (!extra || !actorsWithin(verified.claims.act)) return { kind: "invalid", reason: "shape" };
		const parsed = claimsShape.safeParse(verified.claims);
		if (!parsed.success) return { kind: "invalid", reason: "shape" };
		const claims = parsed.data;
		if (claims.iss !== iss) return { kind: "invalid", reason: "issuer" };
		if (claims.exp * 1000 + allowanceMs <= now()) return { kind: "invalid", reason: "expired" };
		// Times tokens never issues: a token signed past it, or whose iat moved, is no token of tokens'.
		if (!issuedWithin(claims.iat, claims.exp, now())) {
			return { kind: "invalid", reason: "shape" };
		}
		const standing = standingRead(claims.o3co_standing_at, claims.iat);
		if (standing === undefined) return { kind: "invalid", reason: "shape" };
		const bound = Object.entries(claims.cnf ?? {}).map(([member, confirmation]) => ({
			member,
			confirmation,
		}));
		if (bound.length > 1) return { kind: "invalid", reason: "shape" };
		const [binding] = bound;
		const tokenType = binding ? bindings.tokenTypeOf(binding.member) : "Bearer";
		if (!tokenType) return { kind: "invalid", reason: "shape" };
		return {
			kind: "checked",
			issuedAt: claims.iat * 1000,
			access: {
				kind: "valid",
				id: claims.jti,
				expiresAt: claims.exp * 1000,
				standingAt: standing * 1000,
				tokenType,
				...(binding ? { binding: { ...binding, tokenType } } : {}),
				grant: grantOf(claims, extra.added),
			},
		};
	};
}
