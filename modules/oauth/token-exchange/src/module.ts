import { metadataSections, type Section } from "@mod/clients";
import { grants } from "@mod/grants";
import { issuer } from "@mod/issuer";
import { defineModule, setting } from "@mod/kernel";
import { lineage } from "@mod/refresh";
import { sessions } from "@mod/session";
import { sessionTokens } from "@mod/session-tokens";
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
		.pipe(z.number().int().min(1).max(86_400))
		.optional()
		.describe(
			"The longest lifetime an exchange may ask for, from 1s to 1d, even past `tokens`' lifetime.",
		),
});

/** A client's metadata: whether it may present tokens that do not name it, and exchange as a public client. */
const clientSection: Section<{
	readonly "others-tokens": boolean;
	readonly "public-exchange": boolean;
}> = {
	name: "token-exchange",
	schema: z.strictObject({
		"others-tokens": z.boolean().prefault(false),
		"public-exchange": z.boolean().prefault(false),
	}),
};

export default defineModule({ name: "token-exchange", section }, (m) => [
	m.contribute(metadataSections).by(() => clientSection),
	m
		.contribute(exchangeVerifiers)
		.by(async (c) => selfIssued(await c.get(tokens), (await c.get(issuer)).url)),
	m.contribute(grants).by(async (c) => {
		const verifiers = await c.collect(exchangeVerifiers);
		return exchangeGrant({
			verifiers: new Map(verifiers.map((verifier) => [verifier.tokenType, verifier])),
			tokens: await c.get(tokens),
			lineage: await c.get(lineage),
			sessionTokens: await c.get(sessionTokens),
			sessions: await c.get(sessions),
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
]);
