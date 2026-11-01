import { clients, metadataSections } from "@mod/clients";
import { grants } from "@mod/grants";
import { site } from "@mod/http";
import { issuer, metadata } from "@mod/issuer";
import { defineModule, setting } from "@mod/kernel";
import { senderBinding } from "@mod/sender-binding";
import { revocations } from "@mod/subject-revocation";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { z } from "zod";
import { linkedIssuers, linkedSubjects, spentAssertions } from "./contract.ts";
import { acceptsUnbound, delegatedClient } from "./delegated/delegated.ts";
import { grantingWith } from "./granting/granting.ts";
import { idJagProfile } from "./id-jag/id-jag.ts";
import {
	delegatedIn,
	delegatedSetting,
	delegatedTakes,
	type IssuerEntry,
	issuersIn,
	issuersSetting,
	issuersTakes,
	linkedOf,
} from "./issuers/issuers.ts";
import { verifierPolicy } from "./policy/policy.ts";

/** The grant type it serves (RFC 7523). */
export const jwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";

const section = z.strictObject({
	issuers: issuersSetting,
	"delegated-issuers": delegatedSetting,
	"max-assertion-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(1).max(86_400))
		.prefault("1h")
		.describe(
			"How far ahead its `exp` an assertion may be when it is taken, and how far its `exp` may be from its `iat`, from `1s` to `1d` in whole seconds.",
		),
	"clock-skew": setting
		.duration("s")
		.pipe(z.number().int().min(0).max(300))
		.prefault("30s")
		.describe(
			"How far an assertion's times may be off this host's clock, from `0s` to `5m` in whole seconds. Set it no lower than your issuers' real clock drift: narrowing it can admit an assertion a wider skew refused at a revocation.",
		),
});

/** What the grant takes; its own `linkedIssuers` is not named, its own points it collects are. */
const takes = [
	issuer,
	site,
	tokenEndpointLocation,
	spentAssertions,
	revocations,
	linkedSubjects,
	...issuersTakes,
	...delegatedTakes,
];

/** Whether an entry takes the ID-JAG profile, whose DPoP proofs sender binding must read. */
const profiled = (s: z.output<typeof section>) => s.issuers.some((i) => i.profile === "id-jag");

export default defineModule(
	{
		name: "jwt-bearer",
		replicaSafe: true,
		section,
		takes: (s) => [...takes, ...(profiled(s) ? [senderBinding] : [])],
	},
	(m) => [
		m
			.provide(linkedIssuers)
			.by((c) =>
				[...linkedOf(c.section.issuers)].map(([issuer, upstream]) => ({ upstream, issuer })),
			),
		m.contribute(metadataSections).by(() => delegatedClient),
		// The profiles taken, where an entry takes one; never which issuers (draft §9.4).
		m.contribute(metadata).by((c) => ({
			name: "authorization_grant_profiles_supported",
			value: profiled(c.section) ? [idJagProfile] : undefined,
		})),

		m.contribute(grants).by(async (c) => {
			const named = (await c.get(issuer)).url;
			const { url } = await c.get(tokenEndpointLocation);
			// A public origin is required, as written, though the token endpoint has a location without one.
			if ((await c.get(site)).origin === undefined || url === undefined) {
				return c.refuse("jwt-bearer", "the token endpoint's location needs a public origin");
			}
			const spent = await c.get(spentAssertions);
			const boundaries = await c.get(revocations);
			const skewMs = c.section["clock-skew"] * 1000;
			const policyOf = (i: IssuerEntry) =>
				verifierPolicy(i, c.section, { issuer: named, tokenEndpoint: url });
			// An ID-JAG's key is proved by DPoP: unread, a proof would bind nothing and be taken unchecked.
			if (profiled(c.section) && (await c.get(senderBinding)).tokenTypeOf("jkt") === undefined) {
				return c.refuseAll(
					c.section.issuers.flatMap((i, at) =>
						i.profile === "id-jag"
							? [
									{
										where: `jwt-bearer.issuers.${at}.profile`,
										reason: "the ID-JAG profile needs DPoP composed",
									},
								]
							: [],
					),
				);
			}
			const trust = await issuersIn(c, c.section, policyOf, jwtBearerGrantType);
			const delegation = await delegatedIn(c, c.section.issuers, c.section["delegated-issuers"]);
			const refused = [trust, delegation].flatMap((t) => (t.kind === "refused" ? t.refusals : []));
			if (trust.kind === "refused" || delegation.kind === "refused") return c.refuseAll(refused);
			// Told at boot by client: each lets a leaked delegated assertion be used once, before its owner.
			// Only a public client is read for it, and only a delegated issuer's assertion takes it.
			if (c.section["delegated-issuers"].length > 0) {
				for (const client of (await c.get(clients)).registered()) {
					if (client.kind !== "confidential" && acceptsUnbound(client)) {
						c.log.warn("jwt-bearer.accept_unbound", { client: client.id });
					}
				}
			}
			const resolvers = await c.collect(linkedSubjects);
			if (linkedOf(c.section.issuers).size > 0 && resolvers.length === 0) {
				return c.refuse(
					"jwt-bearer.issuers",
					"a linked issuer needs its subjects resolved: compose users, which brings jwt-bearer-users",
				);
			}
			if (resolvers.length > 1) {
				const by = resolvers.map((r) => r.declaredBy).join(", ");
				return c.refuse("jwt-bearer", `more than one module resolves linked subjects: ${by}`);
			}
			return {
				grantType: jwtBearerGrantType,
				...grantingWith({
					issuer: named,
					issuers: c.section.issuers,
					trusted: trust.trusted,
					ledgers: trust.ledgers,
					delegates: delegation.by,
					spent,
					boundaries,
					skewMs,
					resolver: resolvers[0],
					now: c.clock.now,
					log: c.log,
				}),
			};
		}),
	],
);
