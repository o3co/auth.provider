import { createHash } from "node:crypto";
import type { HttpRequest } from "@mod/http";
import { isCanonicalJws, publicMembers } from "@mod/keys";
import type { BindingRead, Scene } from "@mod/sender-binding";
import {
	calculateJwkThumbprint,
	compactVerify,
	decodeProtectedHeader,
	importJWK,
	type JWK,
} from "jose";
import { z } from "zod";
import type { Nonces } from "./nonce.ts";

export interface ProofRules {
	readonly algorithms: readonly string[];
	readonly windowMs: number;
	/** The origin the proof's htu must name; from the issuer, never from the request. */
	readonly origin: string;
	/** Where a server-provided nonce is asked, and how one is made and checked. */
	readonly nonce?: Nonces & { readonly at: "as" | "as+rs" };
}

const claimsShape = z.object({
	htm: z.string(),
	htu: z.string(),
	iat: z.number(),
	// Well-formed, since it becomes a store key.
	jti: z
		.string()
		.min(1)
		.max(256)
		.refine((s) => s.isWellFormed()),
	ath: z.string().optional(),
	nonce: z.string().optional(),
});

type Refused = Extract<BindingRead, { kind: "refused" }>;

export const refused = (description: string): Refused => ({
	kind: "refused",
	error: "invalid_dpop_proof",
	description,
});

/** RFC 9449 §8: the proof is to come again with the nonce given. */
const askNonce = (given: string): Refused => ({
	kind: "refused",
	error: "use_dpop_nonce",
	description: "a proof must carry the nonce given",
	headers: { "dpop-nonce": given },
});

/** A proof that passed every check; its jti is not yet spent. */
type Proved = { readonly kind: "proved"; readonly jkt: string; readonly jti: string };

/** What a proof's check answers; only the caller binds, once it has spent the jti. */
export type ProofRead = Exclude<BindingRead, { kind: "bound" }> | Proved;

/** The origin and path an htu names, or undefined if it is no URL or carries user information. */
function htuTarget(url: string): string | undefined {
	try {
		const parsed = new URL(url);
		if (parsed.username || parsed.password) return undefined;
		return `${parsed.origin}${parsed.pathname}`;
	} catch {
		return undefined;
	}
}

function protectedHeader(proof: string) {
	try {
		return decodeProtectedHeader(proof);
	} catch {
		return undefined;
	}
}

/** The verified payload, or undefined if the key does not import or the signature fails. */
async function verifiedPayload(proof: string, jwk: JWK, alg: string) {
	try {
		const key = await importJWK(jwk, alg);
		return (await compactVerify(proof, key, { algorithms: [alg] })).payload;
	} catch {
		return undefined;
	}
}

function parsedJson(bytes: Uint8Array): unknown {
	try {
		return JSON.parse(new TextDecoder().decode(bytes));
	} catch {
		return undefined;
	}
}

/** Checks a DPoP proof; the jti it returns is for the caller to record once. */
export async function readProof(
	request: HttpRequest,
	scene: Scene,
	rules: ProofRules,
	now: number,
): Promise<ProofRead> {
	const proof = request.headers.get("dpop");
	if (proof === undefined) return { kind: "absent" };
	// Repeated DPoP headers arrive joined by commas; a JWT never holds one.
	if (proof.includes(",")) return refused("one DPoP header only");
	const header = isCanonicalJws(proof) ? protectedHeader(proof) : undefined;
	if (!header) return refused("not a JWT");
	if (header.typ !== "dpop+jwt") return refused("typ must be dpop+jwt");
	if (typeof header.alg !== "string" || !rules.algorithms.includes(header.alg))
		return refused("alg not allowed");
	const jwk = publicMembers(header.jwk) as JWK | undefined;
	if (!jwk) return refused("jwk must be a public key");
	const payload = await verifiedPayload(proof, jwk, header.alg);
	if (!payload) return refused("signature does not verify");
	// JSON.parse never answers undefined, so undefined is a payload that is no JSON.
	const json = parsedJson(payload);
	if (json === undefined) return refused("payload is not JSON");
	const parsed = claimsShape.safeParse(json);
	if (!parsed.success) return refused("missing or malformed claims");
	const claims = parsed.data;
	if (claims.htm !== request.method) return refused("htm does not match");
	if (htuTarget(claims.htu) !== `${rules.origin}${request.path}`)
		return refused("htu does not match");
	if (Math.abs(claims.iat * 1000 - now) > rules.windowMs) return refused("iat outside the window");
	// Asked before the token's hash, as 0.17 did, and before the jti is spent, so the client sends the proof again with the nonce filled in.
	const asking = scene.kind === "issue" || rules.nonce?.at === "as+rs" ? rules.nonce : undefined;
	if (asking && !(claims.nonce !== undefined && asking.verify(claims.nonce))) {
		return askNonce(asking.issue());
	}
	if (scene.kind === "resource") {
		const ath = createHash("sha256").update(scene.token).digest("base64url");
		if (claims.ath !== ath) return refused("ath does not match the token");
	}
	return { kind: "proved", jkt: await calculateJwkThumbprint(jwk, "sha256"), jti: claims.jti };
}
