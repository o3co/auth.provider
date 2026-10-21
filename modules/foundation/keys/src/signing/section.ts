import { z } from "zod";
import { secretProblem } from "../secret/secret.ts";

const kid = z
	.string()
	.regex(/^[A-Za-z0-9._~-]{1,128}$/, "kid is 1 to 128 characters of letters, digits and . _ ~ -");
const asymmetric = z.enum(["EdDSA", "ES256", "RS256"]);
export type AsymmetricAlg = z.output<typeof asymmetric>;

/** Written as PEM, so a placeholder or a key in another form is refused here, before it is read. */
const privatePem = z.string().regex(/^\s*-----BEGIN [A-Z0-9 ]+-----/, "a PEM");

const signingKid = kid.describe(
	"The key id tokens signed with this key carry, unique in the ring.",
);
const signingAlg = "The algorithm the provider signs with.";

const signing = z.discriminatedUnion("alg", [
	z.strictObject({
		kid: signingKid,
		alg: asymmetric.describe(signingAlg),
		"private-key": privatePem.describe("The signing key, as a PKCS8 PEM."),
	}),
	z
		.strictObject({
			kid: signingKid,
			alg: z.literal("HS256").describe(signingAlg),
			secret: z
				.string()
				.describe(
					"The HMAC secret for HS256, its bytes the HMAC key, read as `secret-encoding` names; unset, as hex where the value is whole bytes of hex, else as base64 (64 hex characters are base64 too, so hex is read first). At least 32 bytes, of at least 8 byte values, however read.",
				),
			"secret-encoding": z
				.enum(["hex", "base64", "utf8"])
				.optional()
				.describe(
					"How `secret` is read: `hex`, `base64` (strict) or `utf8`, the text's own bytes, as 0.17 and policy-verifier read it; a value not of the reading named is refused. Unset, hex or else base64.",
				),
		})
		.superRefine((s, ctx) => {
			const reading = { hex: true, encoding: s["secret-encoding"] };
			const problem = secretProblem(s.secret, { atLeast: 32 }, reading);
			if (problem) ctx.addIssue({ code: "custom", message: problem, path: ["secret"] });
		}),
]);

const previous = z.strictObject({
	kid: kid.describe("The key id of a past signing key, unique in the ring."),
	alg: asymmetric.describe("The algorithm the past key signed with."),
	"public-key": z
		.string()
		.min(1)
		.describe("The past key's public half, as PEM; a private PEM is taken too."),
	"expires-at": z.iso
		.datetime({ offset: true })
		.describe("When tokens signed by the past key stop being accepted."),
});

const next = z.strictObject({
	kid: kid.describe("The key id of the key that signs next, unique in the ring."),
	alg: asymmetric.describe("The algorithm the next key will sign with."),
	"public-key": z
		.string()
		.min(1)
		.describe("The next key's public half, as PEM; a private PEM is taken too."),
});

export const section = z
	.strictObject({
		signing: signing.describe("The key the provider signs with now."),
		next: next
			.optional()
			.describe(
				"The key that signs next: published and verifying now, never signing, so verifiers know it before it signs.",
			),
		previous: z
			.array(previous)
			.prefault([])
			.describe("Past signing keys that still verify tokens until each one's `expires-at`."),
	})
	.refine(
		(s) => new Set([s.signing.kid, ...s.previous.map((p) => p.kid)]).size === 1 + s.previous.length,
		{ message: "duplicate kid", path: ["previous"] },
	)
	.refine(
		(s) =>
			s.next === undefined ||
			![s.signing.kid, ...s.previous.map((p) => p.kid)].includes(s.next.kid),
		{ message: "duplicate kid", path: ["next"] },
	);

export type Section = z.output<typeof section>;
