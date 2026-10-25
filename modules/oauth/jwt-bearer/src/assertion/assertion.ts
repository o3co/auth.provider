import type { Reason } from "@mod/external-jwt";
import { Unavailable } from "@mod/kernel";
import { isWellFormedSubject } from "@mod/users";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { z } from "zod";
import { isThumbprint, type Signers } from "../signers.ts";

export type Checked =
	| {
			readonly kind: "valid";
			/** The trusted issuer whose assertion it is read as. */
			readonly entry: string;
			/** The `iss` as sent: the entry's, or a self-issued signer's own name. */
			readonly sentIssuer: string;
			/** The signer it stands for: its `sub`, or a self-issued signer's thumbprint. */
			readonly subject: string;
			readonly jti: string;
			readonly expiresAt: number;
			/** When it says it was made (epoch ms); none when it does not say. */
			readonly issuedAt?: number;
	  }
	| { readonly kind: "invalid"; readonly reason: string };

/** external-jwt's reasons, in this grant's words. */
const said: Readonly<Record<Reason, string>> = {
	malformed: "malformed assertion",
	algorithm: "algorithm not taken",
	"no-key": "untrusted signer",
	"ambiguous-key": "untrusted signer",
	signature: "untrusted signer",
	expired: "expired",
	"not-yet": "not yet valid",
	"future-iat": "issued in the future",
	"too-long": "lives too long",
	issuer: "untrusted signer",
	audience: "wrong audience",
	subject: "wrong subject",
};

/** Text of 1 to 256 well-formed characters: what a `jti` (a store key) and a `kid` (sent to a ledger) must be. */
const bounded = z
	.string()
	.min(1)
	.max(256)
	.refine((s) => s.isWellFormed());

const claimsShape = z.object({ sub: z.string().min(1), jti: bounded });

/** A trusted issuer that takes self-issued signers, by the prefix of their names. */
export interface SelfIssued {
	readonly prefix: string;
	readonly issuer: string;
}

/** The issuer whose self-issued signer an `iss` names, and that signer's thumbprint; none for any other. */
const selfIssuedBy = (iss: string, prefixes: readonly SelfIssued[]) => {
	for (const { prefix, issuer } of prefixes) {
		// Compared as written: no case folding, decoding or normalization.
		const rest = iss.startsWith(prefix) ? iss.slice(prefix.length) : undefined;
		if (rest !== undefined && isThumbprint(rest)) return { issuer, thumbprint: rest };
	}
	return undefined;
};

/**
 * Checks everything but single use: the signer is read unverified, its subject's shape checked,
 * and only then are its keys looked up, among the signers of the issuer the assertion names.
 * Every refusal before the signature holds answers alike, so the answer tells nothing of which
 * signers have keys; one after keeps its own words.
 */
export async function check(
	assertion: string,
	trusted: ReadonlyMap<string, Signers>,
	prefixes: readonly SelfIssued[] = [],
): Promise<Checked> {
	const invalid = (reason: string) => ({ kind: "invalid", reason }) as const;
	const untrusted = invalid("untrusted signer");
	let issuer: unknown;
	let signer: { readonly sub: unknown; readonly kid: unknown };
	try {
		const claims = decodeJwt(assertion);
		issuer = claims.iss;
		signer = { sub: claims.sub, kid: decodeProtectedHeader(assertion).kid };
	} catch {
		return invalid("not a JWT");
	}
	// An issuer is a string, never coerced to one.
	if (typeof issuer !== "string") return untrusted;
	const sentIssuer = issuer;
	// The issuer it names, or the one whose prefix names it a self-issued signer.
	const own = trusted.has(sentIssuer) ? undefined : selfIssuedBy(sentIssuer, prefixes);
	const entry = own?.issuer ?? sentIssuer;
	const signers = trusted.get(entry);
	if (!signers) return untrusted;
	const { sub, kid } = signer;
	if (!isWellFormedSubject(sub)) return untrusted;
	// Read unverified, so bounded before it reaches a key source.
	if (kid !== undefined && !bounded.safeParse(kid).success) return untrusted;
	// A self-issued signer names itself as both; any other's subject is a thumbprint where its issuer says so.
	if (own ? sub !== sentIssuer : signers.thumbprint && !isThumbprint(sub)) return untrusted;
	// The signer as each use reads it: asked for, expected in the signature, and stood for.
	const resolved = own ? own.thumbprint : sub;
	const asked = { lookup: resolved, expectedSub: sub, kid: kid as string | undefined };
	const verifier = await signers.verifierFor(asked);
	if (!verifier) return untrusted;
	const verified = await verifier.verify(assertion);
	if (verified.kind === "unavailable") throw new Unavailable("jwt-bearer");
	if (verified.kind === "invalid")
		return verified.signed ? invalid(said[verified.reason]) : untrusted;
	const parsed = claimsShape.safeParse(verified.claims);
	if (!parsed.success) return invalid("missing or malformed claims");
	if (parsed.data.sub !== asked.expectedSub) return invalid("wrong subject");
	// The verifier read `iat`, where given, as a number.
	const iat = verified.claims.iat;
	return {
		kind: "valid",
		entry,
		sentIssuer,
		subject: resolved,
		jti: parsed.data.jti,
		expiresAt: Number(verified.claims.exp) * 1000,
		...(typeof iat === "number" ? { issuedAt: iat * 1000 } : {}),
	};
}
