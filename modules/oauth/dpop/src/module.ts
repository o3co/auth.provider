import { createHash } from "node:crypto";
import { metadata } from "@mod/issuer";
import { defineModule, setting } from "@mod/kernel";
import { secretBytes } from "@mod/keys";
import { rateLimit } from "@mod/rate-limit";
import { senderBindings } from "@mod/sender-binding";
import { z } from "zod";
import { nonces } from "./nonce.ts";
import { readProof, refused, tooMany } from "./proof.ts";
import { spentProofs } from "./store.ts";

/** The widest `proof-window` the section takes, in seconds: a spent proof is kept by it, whatever is set. */
const widestWindow = 300;

/** The member a proof's key is written in, in a token bound to it. */
const member = "jkt";

/** A spent proof's name: of one length whatever the `jti`; a thumbprint holds no dot, so it is one key's and one `jti`'s alone. */
const spentName = (jkt: string, jti: string) =>
	createHash("sha256").update(`${jkt}.${jti}`).digest("base64url");

const section = z.strictObject({
	algorithms: z
		.array(z.enum(["ES256", "ES384", "EdDSA", "RS256"]))
		.min(1)
		.prefault(["ES256", "ES384", "EdDSA", "RS256"])
		.describe("The signing algorithms a DPoP proof may use."),
	"proof-window": setting
		.duration("s")
		.pipe(z.number().int().min(1).max(widestWindow))
		.prefault("1m")
		.describe(
			"How far a proof's `iat` may lie from the clock on either side, from `1s` to `5m` in whole seconds.",
		),
	proofs: z
		.number()
		.int()
		.min(1)
		.max(100_000)
		.prefault(60)
		.describe(
			"Proofs a token's subject may present at resources in each `proofs-window`, from 1 to 100000.",
		),
	"proofs-window": setting
		.duration("s")
		.pipe(z.number().int().min(1).max(3600))
		.prefault("1m")
		.describe("The window `proofs` is counted over, from `1s` to `1h` in whole seconds."),
	nonce: z
		.strictObject({
			required: z
				.enum(["never", "as", "as+rs"])
				.prefault("as")
				.describe(
					"Where a server-provided nonce is asked: never, at the token endpoint, or there and at resources.",
				),
			ttl: setting
				.duration("s")
				.pipe(z.number().int().min(1).max(3600))
				.prefault("5m")
				.describe(
					"How often the nonce changes, from `1s` to `1h` in whole seconds; one is taken for twice this.",
				),
			secret: secretBytes({ atLeast: 32 })
				.optional()
				.describe(
					"The nonce's key, shared by every instance: base64 of 32 bytes or more; required unless never.",
				),
		})
		.prefault({})
		.superRefine((n, ctx) => {
			if (n.required !== "never" && n.secret === undefined) {
				ctx.addIssue({
					code: "custom",
					path: ["secret"],
					message: "required where a nonce is asked",
				});
			}
		}),
});

/** Kept longer than any proof is accepted by this much, so clock differences never let one back. */
const clockAllowanceMs = 60_000;

export default defineModule(
	// Safe on many instances given the same nonce secret on each: a nonce is an HMAC over a time bucket, kept
	// nowhere (deployment-guarantees, Several instances).
	{ name: "dpop", replicaSafe: true, section, takes: [spentProofs, rateLimit] },
	(m) => [
		m.contribute(senderBindings).by(async (c) => {
			const windowMs = c.section["proof-window"] * 1000;
			const { required, ttl, secret } = c.section.nonce;
			// The operator's choice, yet said at every start: a proof made ahead is taken within its window.
			if (required === "never") {
				c.log.warn("dpop.nonce_not_asked", {
					reason: "no nonce is asked, so a proof made ahead is taken within its window",
				});
			}
			// The section holds a secret wherever a nonce is asked.
			const asked =
				required === "never" || secret === undefined
					? {}
					: {
							nonce: {
								at: required,
								...nonces(Buffer.from(secret, "base64"), ttl * 1000, c.clock.now),
							},
						};
			const rules = { algorithms: c.section.algorithms, windowMs, ...asked };
			const spent = await c.get(spentProofs);
			const counts = await c.get(rateLimit);
			const proofsWindow = { limit: c.section.proofs, ms: c.section["proofs-window"] * 1000 };
			return {
				member,
				name: "dpop",
				tokenType: "DPoP",
				explicit: true,
				read: async (request, scene, issuer) => {
					const origin = new URL(issuer).origin;
					const checked = await readProof(request, scene, { ...rules, origin }, c.clock.now());
					if (checked.kind !== "proved") return checked;
					if (scene.kind === "resource") {
						const { held, subject } = scene;
						// Not the holder's: `sender-binding` refuses it, with nothing counted or spent.
						if (held.member !== member || held.confirmation !== checked.jkt) {
							return { kind: "bound", confirmation: checked.jkt };
						}
						// By subject, as a token's holder picks its key. Past the proof, so a copy of a token alone counts
						// nothing, and here, as a token another kind holds makes no such write.
						const counted = await counts.hit("dpop.proofs", subject, proofsWindow);
						if (counted.kind === "limited") return tooMany(counted.retryAfterMs);
					}
					// A proof is accepted within the window on either side of its iat, so it is
					// remembered for twice the widest window from now, not the one in force: a window
					// widened later on the same store never outlasts it.
					const recorded = await spent.save(
						spentName(checked.jkt, checked.jti),
						2 * widestWindow * 1000 + clockAllowanceMs,
					);
					if (recorded !== "created") return refused("proof used before");
					return { kind: "bound", confirmation: checked.jkt };
				},
			};
		}),
		m.contribute(metadata).by((c) => ({
			name: "dpop_signing_alg_values_supported",
			value: c.section.algorithms,
		})),
	],
);
