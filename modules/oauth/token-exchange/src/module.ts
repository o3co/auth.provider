import { metadataSections, type Section } from "@mod/clients";
import { grants } from "@mod/grants";
import { issuer } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { lineage } from "@mod/refresh";
import { sessions } from "@mod/session";
import { sessionTokens } from "@mod/session-tokens";
import { tokens } from "@mod/tokens";
import { z } from "zod";
import { selfIssued } from "./answer.ts";
import { exchangeVerifiers } from "./contract.ts";
import { exchangeGrant } from "./exchange.ts";

const section = z.strictObject({
	"max-actor-depth": z.number().int().min(1).max(10).default(3),
	"max-lifetime-seconds": z.number().int().min(1).max(86_400).optional(),
});

/** A client's metadata: whether it may present tokens that do not name it. */
const othersTokens: Section<{ readonly "others-tokens": boolean }> = {
	name: "token-exchange",
	schema: z.strictObject({ "others-tokens": z.boolean().default(false) }),
};

export default defineModule({ name: "token-exchange", section }, (m) => [
	m.contribute(metadataSections).by(() => othersTokens),
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
			...(c.section["max-lifetime-seconds"] === undefined
				? {}
				: { maxLifetimeSeconds: c.section["max-lifetime-seconds"] }),
			othersTokens: (client) => client.section(othersTokens)["others-tokens"],
			now: c.clock.now,
		});
	}),
]);
