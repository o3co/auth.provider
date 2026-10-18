import { createHash } from "node:crypto";
import type { Algorithm, ExternalJwt, JwksSource } from "@mod/external-jwt";
import { type Clock, Unavailable } from "@mod/kernel";
import { type UpstreamLogin, type UpstreamProfile, UpstreamRefused } from "@mod/upstreams";
import { z } from "zod";

/** What a type expects of its upstream's id_tokens. */
export interface IdTokenRules {
	readonly issuer: string;
	readonly client: string;
	readonly jwks: JwksSource;
	readonly algorithms: readonly Algorithm[];
	readonly skewMs: number;
	/** Takes one audience whose `azp` names another client; otherwise a given `azp` is the client. */
	readonly crossClient?: boolean;
	/** The `email_verified` values by which the upstream says it verified the email. */
	readonly emailVerified: readonly (true | "true")[];
	/** What is unavailable when no key set can be had. */
	readonly what: string;
}

/** What a checked id_token says of the login, and its claims for a type to read more. */
export interface IdTokenLogin {
	readonly login: Pick<UpstreamLogin, "subject" | "authenticatedAt" | "profile">;
	readonly claims: Readonly<Record<string, unknown>>;
}

const idTokenClaims = z.looseObject({
	sub: z.string().min(1),
	aud: z.unknown(),
	azp: z.string().optional(),
	/** Required (OpenID Connect Core §2); external-jwt checks its value. */
	iat: z.number(),
	auth_time: z.number().nonnegative().optional(),
	nonce: z.unknown().optional(),
});

/** The profile in checked claims (OpenID Connect Core §5.1): text kept as text. */
function profileOf(
	said: Readonly<Record<string, unknown>>,
	verifiedBy: IdTokenRules["emailVerified"],
): UpstreamProfile | undefined {
	const { email, email_verified: verified, name, picture } = said;
	const emailVerified = verifiedBy.some((value) => value === verified);
	const profile = {
		...(typeof email === "string" ? { email, emailVerified } : {}),
		...(typeof name === "string" ? { name } : {}),
		...(typeof picture === "string" ? { picture } : {}),
	};
	return Object.keys(profile).length > 0 ? profile : undefined;
}

const sha = (name: string) => (token: string) => createHash(name).update(token, "ascii").digest();
const shake256 = (token: string) =>
	createHash("shake256", { outputLength: 114 }).update(token, "ascii").digest();

/** The digests `at_hash` may be taken with under a signature's algorithm: EdDSA's header names no curve. */
function atHashDigestsOf(alg: string): readonly ((token: string) => Buffer)[] {
	const bits = /^(?:RS|PS|ES)(256|384|512)$/.exec(alg)?.[1];
	if (bits) return [sha(`sha${bits}`)];
	if (alg === "Ed25519") return [sha("sha512")];
	if (alg === "Ed448") return [shake256];
	if (alg === "EdDSA") return [sha("sha512"), shake256];
	return [];
}

/**
 * Whether a checked id_token's `at_hash`, where it gives one, is the left half of the access token's
 * digest by its signature's algorithm (OpenID Connect Core §3.1.3.6); one that is not text, or under
 * an algorithm with no digest known, does not hold.
 */
export function atHashHolds(idToken: string, atHash: unknown, accessToken: string): boolean {
	if (atHash === undefined) return true;
	if (typeof atHash !== "string") return false;
	const [header = ""] = idToken.split(".");
	const { alg } = JSON.parse(Buffer.from(header, "base64url").toString("utf8")) as {
		alg?: unknown;
	};
	if (typeof alg !== "string") return false;
	return atHashDigestsOf(alg).some((digest) => {
		const full = digest(accessToken);
		return atHash === full.subarray(0, full.length / 2).toString("base64url");
	});
}

/**
 * Reads an id_token once it holds for this client and login (OpenID Connect Core §3.1.3.7), and,
 * given the access token answered beside it, its `at_hash`.
 */
export function idTokenReaderOf(
	jwt: ExternalJwt,
	rules: IdTokenRules,
	clock: Clock,
): (idToken: string, nonce: string, accessToken?: string) => Promise<IdTokenLogin> {
	const { client, skewMs } = rules;
	const verifier = jwt.verifierOf(
		{ jwks: rules.jwks },
		{ algorithms: rules.algorithms, skewMs, expect: { iss: rules.issuer, aud: [client] } },
	);
	return async (idToken, nonce, accessToken) => {
		const checked = await verifier.verify(idToken);
		if (checked.kind === "unavailable") throw new Unavailable(rules.what);
		if (checked.kind === "invalid") throw new UpstreamRefused();
		const read = idTokenClaims.safeParse(checked.claims);
		if (!read.success) throw new UpstreamRefused();
		const { sub, aud, azp, auth_time, nonce: carried } = read.data;
		// Several audiences: the client must be the authorized party.
		if (Array.isArray(aud) && aud.length !== 1 && azp !== client) throw new UpstreamRefused();
		// A given authorized party is the client too, unless the type takes cross-client identity.
		if (!rules.crossClient && azp !== undefined && azp !== client) throw new UpstreamRefused();
		const authenticatedAt = auth_time === undefined ? undefined : auth_time * 1000;
		// No login time past our clock by more than the skew.
		if (authenticatedAt !== undefined && authenticatedAt > clock.now() + skewMs) {
			throw new UpstreamRefused();
		}
		if (carried !== nonce) throw new UpstreamRefused();
		if (accessToken !== undefined && !atHashHolds(idToken, checked.claims.at_hash, accessToken)) {
			throw new UpstreamRefused();
		}
		const profile = profileOf(checked.claims, rules.emailVerified);
		const login = {
			subject: sub,
			...(authenticatedAt === undefined ? {} : { authenticatedAt }),
			...(profile === undefined ? {} : { profile }),
		};
		return { login, claims: checked.claims };
	};
}
