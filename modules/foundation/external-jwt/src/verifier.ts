import { type Clock, deepFreeze } from "@mod/kernel";
import { isCanonicalJws } from "@mod/keys";
import type { Outbound } from "@mod/outbound";
import { compactVerify, decodeProtectedHeader } from "jose";
import type {
	Algorithm,
	ExternalJwt,
	JwksSource,
	KeySource,
	Policy,
	Reason,
	Verified,
	Verifier,
} from "./contract.ts";
import { jwksAt, type KeySet } from "./jwks.ts";
import { algorithms, type Candidate, fromJwk, fromPem, isAlgorithm, picked } from "./keys.ts";

type Claims = Readonly<Record<string, unknown>>;

/** The one key for a header's algorithm and id, or why there is none. */
type Choose = (
	alg: Algorithm,
	kid: string | undefined,
) => Promise<Candidate | "no-key" | "ambiguous-key" | "unavailable">;

/** A `typ` as RFC 7515 compares it: without case and without `application/`. */
const mediaTypeOf = (typ: unknown) =>
	typeof typ === "string" ? typ.toLowerCase().replace(/^application\//, "") : undefined;
/** Claims are UTF-8, as RFC 7519 says; bytes that are not refuse them. */
const utf8 = new TextDecoder("utf-8", { fatal: true });
const isTime = (value: unknown): value is number =>
	typeof value === "number" && Number.isFinite(value);

/** Verifiers on `kernel`'s clock, fetching key sets through `outbound`, each set kept once by its URL and hosts. */
export function externalJwtOver(deps: {
	readonly clock: Clock;
	readonly outbound: Outbound;
	/** How long after it was fetched a key set may still be used. */
	readonly keySetMaxAgeMs: number;
}): ExternalJwt {
	const sets = new Map<string, KeySet>();
	const setAt = ({ url, hosts: written, internal }: JwksSource) => {
		// A host is one name whatever its case or the root's trailing dot.
		const hosts = [...new Set(written.map((h) => h.toLowerCase().replace(/\.$/, "")))].sort();
		// One fetched as the operator's URL is never shared with one that is not.
		const key = JSON.stringify([url, hosts, internal ?? null]);
		const kept = sets.get(key);
		if (kept) return kept;
		const made = jwksAt(
			{ url, hosts, ...(internal === undefined ? {} : { internal }) },
			{ clock: deps.clock, outbound: deps.outbound, maxAgeMs: deps.keySetMaxAgeMs },
		);
		sets.set(key, made);
		return made;
	};
	const chooserOf = (keys: KeySource): Choose => {
		if ("jwks" in keys) return fromSet(setAt(keys.jwks));
		const written =
			"inline" in keys
				? keys.inline.flatMap((jwk) => fromJwk(jwk) ?? [])
				: keys.pem.flatMap((given) => fromPem(given) ?? []);
		return async (alg, kid) => picked(written, alg, kid);
	};
	return {
		algorithms,
		verifierOf: (keys, policy) => verifierWith(chooserOf(keys), policy, deps.clock),
	};
}

/** Picks from the kept set, and from a fresh one only when the kept set has no key that fits. */
function fromSet(set: KeySet): Choose {
	return async (alg, kid) => {
		const held = await set.keys();
		const first = held ? picked(held, alg, kid) : undefined;
		// An ambiguous pick is the set's own answer; fetching again would not settle it.
		if (first !== undefined && first !== "no-key") return first;
		const again = await set.again();
		return again ? picked(again, alg, kid) : "unavailable";
	};
}

function headerOf(jwt: string): Record<string, unknown> | undefined {
	try {
		return decodeProtectedHeader(jwt) as Record<string, unknown>;
	} catch {
		return undefined;
	}
}

async function signedPayload(jwt: string, key: Candidate) {
	try {
		return (await compactVerify(jwt, key.key)).payload;
	} catch {
		return undefined;
	}
}

/** One JSON object in UTF-8, or undefined. */
function claimsOf(payload: Uint8Array): Claims | undefined {
	try {
		const claims: unknown = JSON.parse(utf8.decode(payload));
		return typeof claims === "object" && claims !== null ? (claims as Claims) : undefined;
	} catch {
		return undefined;
	}
}

/** What is wrong with the claims under the policy at `now`, if anything. */
function claimsFault(claims: Claims, policy: Policy, now: number): Reason | undefined {
	const { exp, nbf, iat } = claims;
	if (!isTime(exp) || (nbf !== undefined && !isTime(nbf)) || (iat !== undefined && !isTime(iat))) {
		return "malformed";
	}
	const [expMs, nbfMs, iatMs] = [
		exp * 1000,
		isTime(nbf) ? nbf * 1000 : undefined,
		isTime(iat) ? iat * 1000 : undefined,
	];
	const skew = policy.skewMs;
	if (expMs <= now - skew) return "expired";
	if (nbfMs !== undefined && nbfMs > now + skew) return "not-yet";
	if (iatMs !== undefined && iatMs > now + skew) return "future-iat";
	if (policy.maxLifetimeMs !== undefined) {
		const reach = policy.maxLifetimeMs + skew;
		if (expMs - now > reach || (iatMs !== undefined && now - iatMs > reach)) return "too-long";
	}
	const expected = policy.expect;
	if (expected?.iss !== undefined && claims.iss !== expected.iss) return "issuer";
	const wanted = expected?.aud;
	if (wanted !== undefined) {
		const audiences = typeof claims.aud === "string" ? [claims.aud] : claims.aud;
		// A list of audiences holds only strings, as RFC 7519 says.
		const allStrings = Array.isArray(audiences) && audiences.every((a) => typeof a === "string");
		if (!allStrings || !audiences.some((a) => wanted.includes(a))) return "audience";
	}
	if (expected?.sub !== undefined && claims.sub !== expected.sub) return "subject";
	return undefined;
}

function verifierWith(choose: Choose, policy: Policy, clock: Clock): Verifier {
	const invalid = (reason: Reason): Verified => ({ kind: "invalid", reason });
	return {
		verify: async (jwt) => {
			const header = isCanonicalJws(jwt) ? headerOf(jwt) : undefined;
			if (!header) return invalid("malformed");
			// A JWT is encoded, and no critical extension is taken.
			if (header.b64 !== undefined || header.crit !== undefined) return invalid("malformed");
			if (policy.typ !== undefined && mediaTypeOf(header.typ) !== mediaTypeOf(policy.typ))
				return invalid("malformed");
			const kid = header.kid;
			if (kid !== undefined && typeof kid !== "string") return invalid("malformed");
			const alg = header.alg;
			if (!isAlgorithm(alg) || !policy.algorithms.includes(alg)) return invalid("algorithm");
			const key = await choose(alg, kid);
			if (key === "unavailable") return { kind: "unavailable" };
			if (typeof key === "string") return invalid(key);
			const payload = await signedPayload(jwt, key);
			if (!payload) return invalid("signature");
			const claims = claimsOf(payload);
			if (!claims) return invalid("malformed");
			const fault = claimsFault(claims, policy, clock.now());
			if (fault) return invalid(fault);
			return { kind: "valid", header: deepFreeze({ ...header }), claims: deepFreeze(claims) };
		},
	};
}
