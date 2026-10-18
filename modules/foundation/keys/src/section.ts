import { z } from "zod";
import { secretBytes } from "./secret.ts";

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
	z.strictObject({
		kid: signingKid,
		alg: z.literal("HS256").describe(signingAlg),
		secret: secretBytes({ atLeast: 32 }, { hex: true }).describe(
			"The HMAC secret for HS256: at least 32 bytes, in hex or base64, of at least 8 byte values.",
		),
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
