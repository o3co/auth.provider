import { clients, metadataSections, type Section } from "@mod/clients";
import { grants, tokenTies } from "@mod/grants";
import { issuer } from "@mod/issuer";
import { defineModule, setting } from "@mod/kernel";
import { tokens } from "@mod/tokens";
import { z } from "zod";
import { selfIssued } from "./answer.ts";
import { exchangeVerifiers } from "./contract.ts";
import { exchangeGrant } from "./exchange.ts";

const section = z.strictObject({
	"max-actor-depth": z
		.number()
		.int()
		.min(1)
		.max(10)
		.prefault(3)
		.describe("The longest chain of actors an exchanged token may carry."),
	"max-lifetime": setting
		.duration("s")
		// From two seconds, the shortest lifetime `tokens` issues.
		.pipe(z.number().int().min(2).max(86_400))
		.optional()
		.describe(
			"The longest lifetime an exchange may ask for, from 2s to 1d, even past `tokens`' lifetime.",
		),
});

/** A client's metadata: whether it may present tokens that do not name it, and exchange as a public client. */
const clientSection: Section<{
	readonly "others-tokens": boolean;
	readonly "public-exchange": boolean;
}> = {
	name: "token-exchange",
	schema: z.strictObject({
		"others-tokens": z
			.boolean()
			.prefault(false)
			.describe(
				"Whether the client may present subject and actor tokens that do not name it, by issued-to or audience.",
			),
		"public-exchange": z
			.boolean()
			.prefault(false)
			.describe(
				"Whether the client, when public, may exchange; a confidential client allowed the grant always may.",
			),
	}),
};

export default defineModule(
	// Its own verifiers are collected, so named; the tokens, the issuer and the ties are others'.
	{
		name: "token-exchange",
		replicaSafe: true,
		section,
		takes: [tokens, issuer, exchangeVerifiers, tokenTies, clients],
	},
	(m) => [
		m.contribute(metadataSections).by(() => clientSection),
		m
			.contribute(exchangeVerifiers)
			.by(async (c) => selfIssued(await c.get(tokens), (await c.get(issuer)).url)),
		m.contribute(grants).by(async (c) => {
			const issuing = await c.get(tokens);
			// An exchange issues anew from a token made before a subject's revocation, so its subject must be checked.
			if (!issuing.subjectsChecked()) {
				return c.refuse(
					"token-exchange",
					"tokens.subject-check is none, so a token made before a subject's revocation could be exchanged for a new one: compose a subject check and leave tokens.subject-check unset, or leave token-exchange out",
				);
			}
			// Told at every start by client: each exchanges more than its own tokens, or while public.
			for (const client of (await c.get(clients)).registered()) {
				const { "others-tokens": others, "public-exchange": publicly } =
					client.section(clientSection);
				if (publicly) c.log.warn("token-exchange.public_exchange", { client: client.id });
				if (others) c.log.warn("token-exchange.others_tokens", { client: client.id });
			}
			const verifiers = await c.collect(exchangeVerifiers);
			return exchangeGrant({
				verifiers: new Map(verifiers.map((verifier) => [verifier.tokenType, verifier])),
				tokens: issuing,
				ties: await c.collect(tokenTies),
				issuer: (await c.get(issuer)).url,
				maxActorDepth: c.section["max-actor-depth"],
				...(c.section["max-lifetime"] === undefined
					? {}
					: { maxLifetimeSeconds: c.section["max-lifetime"] }),
				othersTokens: (client) => client.section(clientSection)["others-tokens"],
				publicExchange: (client) => client.section(clientSection)["public-exchange"],
				now: c.clock.now,
			});
		}),
	],
);
