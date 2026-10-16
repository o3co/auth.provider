import type { Reason, Verifier } from "@mod/external-jwt";
import { Unavailable } from "@mod/kernel";
import { decodeJwt } from "jose";
import { z } from "zod";

export type Checked =
	| {
			readonly kind: "valid";
			readonly issuer: string;
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

const claimsShape = z.object({
	sub: z.string().min(1),
	// Well-formed, since it becomes a store key.
	jti: z
		.string()
		.min(1)
		.max(256)
		.refine((s) => s.isWellFormed()),
});

/** Checks everything but single use, with the verifier of the issuer the assertion names. */
export async function check(
	assertion: string,
	trusted: ReadonlyMap<string, Verifier>,
): Promise<Checked> {
	const invalid = (reason: string) => ({ kind: "invalid", reason }) as const;
	let issuer: string;
	try {
		issuer = String(decodeJwt(assertion).iss);
	} catch {
		return invalid("not a JWT");
	}
	const verifier = trusted.get(issuer);
	if (!verifier) return invalid("untrusted signer");
	const verified = await verifier.verify(assertion);
	if (verified.kind === "unavailable") throw new Unavailable("jwt-bearer");
	if (verified.kind === "invalid") return invalid(said[verified.reason]);
	const parsed = claimsShape.safeParse(verified.claims);
	if (!parsed.success) return invalid("missing or malformed claims");
	// The verifier read `iat`, where given, as a number.
	const iat = verified.claims.iat;
	return {
		kind: "valid",
		issuer,
		subject: parsed.data.sub,
		jti: parsed.data.jti,
		expiresAt: Number(verified.claims.exp) * 1000,
		...(typeof iat === "number" ? { issuedAt: iat * 1000 } : {}),
	};
}
