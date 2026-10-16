import { metadata } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { secretBytes } from "@mod/keys";
import { senderBindings } from "@mod/sender-binding";
import { z } from "zod";
import { nonces } from "./nonce.ts";
import { readProof, refused } from "./proof.ts";
import { spentProofs } from "./store.ts";

const section = z.strictObject({
	algorithms: z
		.array(z.enum(["ES256", "ES384", "EdDSA", "RS256"]))
		.min(1)
		.default(["ES256", "ES384", "EdDSA", "RS256"])
		.describe("The signing algorithms a DPoP proof may use."),
	"proof-window-seconds": z
		.number()
		.int()
		.min(1)
		.max(300)
		.default(60)
		.describe("How far a proof's `iat` may lie from the clock on either side, in seconds."),
	nonce: z
		.strictObject({
			required: z
				.enum(["never", "as", "as+rs"])
				.default("never")
				.describe(
					"Where a server-provided nonce is asked: never, at the token endpoint, or there and at resources.",
				),
			"ttl-seconds": z
				.number()
				.int()
				.min(1)
				.max(3600)
				.default(300)
				.describe("How often the nonce changes, in seconds; one is taken for twice this."),
			secret: secretBytes({ atLeast: 32 })
				.optional()
				.describe(
					"The nonce's key, shared by every instance: base64 of 32 bytes or more; required unless never.",
				),
		})
		.default({ required: "never", "ttl-seconds": 300 })
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

export default defineModule({ name: "dpop", section }, (m) => [
	m.contribute(senderBindings).by(async (c) => {
		const windowMs = c.section["proof-window-seconds"] * 1000;
		const { required, "ttl-seconds": ttl, secret } = c.section.nonce;
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
		return {
			member: "jkt",
			name: "dpop",
			tokenType: "DPoP",
			explicit: true,
			read: async (request, scene, issuer) => {
				const origin = new URL(issuer).origin;
				const checked = await readProof(request, scene, { ...rules, origin }, c.clock.now());
				if (checked.kind !== "proved") return checked;
				// A proof is accepted within the window on either side of its iat, so it is
				// remembered for twice the window from now.
				// A thumbprint holds no dot, so the name is one key's and one jti's alone.
				const recorded = await spent.save(
					`${checked.jkt}.${checked.jti}`,
					2 * windowMs + clockAllowanceMs,
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
]);
