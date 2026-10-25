import { createHash } from "node:crypto";
import type { Verifier as JwtVerifier } from "@mod/external-jwt";
import { Unavailable } from "@mod/kernel";
import type { Revocations } from "@mod/subject-revocation";
import type { ExchangeVerifier } from "@mod/token-exchange";
import { isWellFormedSubject, type Users } from "@mod/users";
import { decodeJwt } from "jose";
import { z } from "zod";
import type { IdTokenChecks, IdTokenTaken } from "./contract.ts";
import { type ClientEntry, type Kind, longestClockSkew, longestMaxAge } from "./section.ts";
import type { UsedIdTokens } from "./store.ts";

export const idTokenType = "urn:ietf:params:oauth:token-type:id_token";

/** One kind taken: its upstream's name, its issuers, its keys' verifier, and the clients it serves. */
export interface Taken {
	readonly kind: Kind;
	readonly upstream: string;
	readonly iss: readonly [string, ...string[]];
	readonly jwt: JwtVerifier;
	readonly clients: readonly (readonly [string, ClientEntry])[];
}

export interface VerifierParts {
	readonly taken: readonly Taken[];
	readonly users: Pick<Users, "byUpstream">;
	readonly revocations: Pick<Revocations, "compare">;
	readonly used: UsedIdTokens;
	readonly now: () => number;
	readonly maxAgeMs: number;
	readonly skewMs: number;
}

/** Kept past the last moment a token is taken by this much, so clock differences never let one back. */
const usedAllowanceMs = 60_000;
/** The latest any section takes an id_token after its `iat`, and after its `exp`: the longest max-age and clock skew. */
const longestAgeMs = longestMaxAge * 1000;
const longestSkewMs = longestClockSkew * 1000;

const claimsShape = z.object({
	iss: z.string(),
	sub: z.string().refine(isWellFormedSubject),
	aud: z.union([z.string(), z.array(z.string())]),
	azp: z.string().optional(),
	iat: z.number(),
	exp: z.number(),
	nonce: z.string().optional(),
});
/** A nonce that can name a key: the 43 characters of a SHA-256 digest in base64url. */
const digestShape = /^[A-Za-z0-9_-]{43}$/;

/** Whether a client takes an id_token for `aud` from `azp`. */
const takes = (entry: ClientEntry, aud: string, azp: string | undefined) =>
	entry.audiences.includes(aud) &&
	(entry["authorized-parties"].length === 0
		? azp === undefined || azp === aud
		: azp !== undefined && entry["authorized-parties"].includes(azp));

/** The checks over the kinds taken, choosing the kind by `iss`. */
export function idTokenChecksOver(parts: VerifierParts): IdTokenChecks {
	const invalid = { kind: "invalid" } as const;
	const kindOf = (token: string) => {
		try {
			const { iss } = decodeJwt(token);
			return parts.taken.find((taken) => typeof iss === "string" && taken.iss.includes(iss));
		} catch {
			return undefined;
		}
	};
	return {
		issuers: parts.taken.flatMap((taken) => taken.iss),
		async check(token) {
			const taken = kindOf(token);
			if (!taken) return invalid;
			const verified = await taken.jwt.verify(token);
			if (verified.kind === "unavailable") throw new Unavailable("exchange-id-tokens");
			if (verified.kind === "invalid") return invalid;
			const read = claimsShape.safeParse(verified.claims);
			if (!read.success) return invalid;
			const { sub, aud, azp, iat, exp, nonce } = read.data;
			if (parts.now() - iat * 1000 > parts.maxAgeMs + parts.skewMs) return invalid;
			const audiences = typeof aud === "string" ? [aud] : aud;
			const clients = taken.clients
				.filter(([, entry]) => audiences.some((one) => takes(entry, one, azp)))
				.map(([id]) => id);
			// One app's id_token is one client's; an id_token two clients would take is no one's.
			if (clients.length !== 1) return invalid;
			const found = await parts.users.byUpstream(taken.upstream, sub);
			if (found.kind !== "user") return invalid;
			const subject = found.user.subject;
			// Widened by the skew: an issuer's clock running ahead could put a token issued before the revocation after it.
			const revoked = await parts.revocations.compare(
				subject,
				iat * 1000,
				"sessions",
				parts.skewMs,
			);
			if (revoked === "revoked") return invalid;
			const answer: IdTokenTaken = {
				kind: "taken",
				subject,
				issuer: taken.iss[0] as string,
				issuedAt: iat * 1000,
				expiresAt: exp * 1000,
				client: clients[0] as string,
				...(nonce !== undefined && digestShape.test(nonce) ? { holderDigest: nonce } : {}),
			};
			return answer;
		},
		async consume(token) {
			const taken = kindOf(token);
			const { iat, exp } = decodeJwt(token);
			if (!taken || typeof iat !== "number" || typeof exp !== "number") {
				throw new Unavailable("exchange-id-tokens");
			}
			// The signed part alone, so the same token under another signature is the same token.
			const signed = token.split(".").slice(0, 2).join(".");
			const name = createHash("sha256").update(signed).digest("base64url");
			// By the longest a section may take it, never this one's: a record outlives any section's taking, so
			// instances on other settings, or this one's widened, never take it again.
			const lastTaken = Math.min(exp * 1000, iat * 1000 + longestAgeMs) + longestSkewMs;
			// Relative, since the place judges a lifetime by its own clock.
			const lifetimeMs = lastTaken - parts.now() + usedAllowanceMs;
			const saved = await parts.used.save(taken.kind, name, lifetimeMs);
			return saved === "created" ? "consumed" : "replayed";
		},
	};
}

/** The id_token verifier for token-exchange, over the checks: one per token type. */
export function idTokens(checks: IdTokenChecks): ExchangeVerifier {
	return {
		tokenType: idTokenType,
		async verify(token) {
			const taken = await checks.check(token);
			if (taken.kind !== "taken") return { kind: "invalid" };
			const { subject, issuer, expiresAt, client, holderDigest } = taken;
			// Another issuer's token for one app: what it may give is that client's allowance alone.
			return {
				kind: "foreign",
				subject,
				issuer,
				expiresAt,
				clients: [client],
				...(holderDigest === undefined ? {} : { holderDigest }),
			};
		},
		consume: (token) => checks.consume(token),
	};
}
