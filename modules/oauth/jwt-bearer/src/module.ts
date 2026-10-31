import { createHash } from "node:crypto";
import { type Ceiling, clientAllowance } from "@mod/client-allowance";
import { clients, metadataSections } from "@mod/clients";
import { type GrantInput, type GrantOutcome, grants, type Refused } from "@mod/grants";
import { site } from "@mod/http";
import { issuer, metadata } from "@mod/issuer";
import { defineModule, setting } from "@mod/kernel";
import { senderBinding } from "@mod/sender-binding";
import { revocations } from "@mod/subject-revocation";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { z } from "zod";
import { check } from "./assertion/assertion.ts";
import { bindingOf, identifiedBy, identifiedOf, unidentified } from "./clientless/clientless.ts";
import { meets } from "./conditions/conditions.ts";
import {
	type DelegatedAssertions,
	linkedIssuers,
	linkedSubjects,
	spentAssertions,
} from "./contract.ts";
import {
	acceptsUnbound,
	checkedBy,
	delegatedClient,
	holds,
	sentIssuerOf,
	spentBy,
} from "./delegated/delegated.ts";
import {
	admit,
	asked as askedOf,
	type IdJag,
	idJagProfile,
	namesIdJag,
	read,
	recheck,
} from "./id-jag/id-jag.ts";
import {
	delegatedIn,
	delegatedSetting,
	delegatedTakes,
	type IssuerEntry,
	issuersIn,
	issuersSetting,
	issuersTakes,
	linkedOf,
	selfIssuedOf,
} from "./issuers/issuers.ts";
import { spentIn } from "./ledgers.ts";
import { ceilingsOf, keepUntilOf, verifierPolicy } from "./policy/policy.ts";

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
			"How far an assertion's times may be off this host's clock, from `0s` to `5m` in whole seconds.",
		),
});

/** A spent assertion's name; JSON keeps the issuer and the jti apart, whatever either holds. */
const spentName = (issuer: string, jti: string) =>
	createHash("sha256")
		.update(JSON.stringify([issuer, jti]))
		.digest("base64url");

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
			const { trusted, ledgers } = trust;
			const entries = new Map(c.section.issuers.map((i) => [i.issuer, i]));
			// Told at boot by client: each lets a leaked delegated assertion be used once, before its owner.
			for (const client of (await c.get(clients)).registered()) {
				if (acceptsUnbound(client)) c.log.warn("jwt-bearer.accept_unbound", { client: client.id });
			}
			const selfIssued = selfIssuedOf(c.section.issuers);
			const linked = linkedOf(c.section.issuers);
			const resolvers = await c.collect(linkedSubjects);
			if (linked.size > 0 && resolvers.length === 0) {
				return c.refuse(
					"jwt-bearer.issuers",
					"a linked issuer needs its subjects resolved: compose users, which brings jwt-bearer-users",
				);
			}
			if (resolvers.length > 1) {
				const by = resolvers.map((r) => r.declaredBy).join(", ");
				return c.refuse("jwt-bearer", `more than one module resolves linked subjects: ${by}`);
			}
			const [resolver] = resolvers;
			/** The subject a verified signer stands for: its sub, or for a linked issuer the one resolved, none where none is. */
			const subjectOf = async (from: string, sub: string) => {
				const name = linked.get(from);
				if (name === undefined || resolver === undefined) return sub;
				const found = await resolver.subjectOf(name, sub);
				return found.kind === "subject" ? found.subject : undefined;
			};
			const refusedGrant = (description: string) =>
				({ kind: "error", error: "invalid_grant", description }) as const;
			/**
			 * Sorted by type before every way an assertion goes, delegated or named or none, before anything
			 * is verified: an ID-JAG, which no entry yet takes, is refused as an unknown signer is.
			 */
			const sortedOut = (assertion: string) => {
				const takesProfile = entries.get(sentIssuerOf(assertion) ?? "")?.profile === "id-jag";
				return namesIdJag(assertion) === takesProfile
					? undefined
					: refusedGrant("untrusted signer");
			};
			const anotherClient = refusedGrant("assertion is for another client");
			const assertionRequired = {
				kind: "error",
				error: "invalid_request",
				description: "assertion is required",
			} as const;
			const binding = bindingOf(c.section.issuers);
			/** Where every assertion of a trusted issuer is checked, whether a request names its client or none. */
			const verify = (assertion: string) => check(assertion, trusted, selfIssued);
			/**
			 * What any assertion verified becomes: a token for its subject, once the client may have it and
			 * its single use is spent. It must have a second left when it is spent; a token with less than a
			 * second left once signed, however long the steps before take, `tokens` refuses.
			 */
			const issueFor = async (
				{ client, param, admits, issue, target }: GrantInput,
				checked: {
					readonly subject: string;
					readonly issuedAt?: number;
					readonly expiresAt: number;
				},
				spend: () => Promise<"spent" | "replayed">,
				/** The ceilings its issuer holds its tokens to, within the client's allowance. */
				ceilings: readonly Ceiling[],
				/** An ID-JAG's: the scope it asks, and what it checks again before anything is used up. */
				profile?: IdJag,
			): Promise<GrantOutcome | Refused> => {
				const want = profile ? askedOf(profile, param("scope")) : undefined;
				const allowed = clientAllowance.allowedIssuanceWithin(
					client,
					want ? [...ceilings, want.ceiling] : ceilings,
					want ? want.scope : param("scope"),
					named,
				);
				if (allowed.kind === "error") return allowed;
				const within = want ? [...ceilings, want.ceiling] : ceilings;
				const asked = target(allowed.audience, (a) =>
					clientAllowance.allowsAudienceWithin(client, within, a, named),
				);
				if (asked.kind === "error") return asked;
				const again =
					profile && recheck(profile, { scope: allowed.scope, audience: asked.audience });
				if (again?.kind === "error") return { kind: "error", error: again.error };
				// Made at its `iat`, never later than now; one that does not say is as old as can be. The
				// boundary is widened by the section's skew, as an issuer's clock may run that far ahead: an
				// issuer's own narrower skew narrows what is taken, never this, so narrowing it lets none back.
				const madeAt = Math.min(checked.issuedAt ?? 0, c.clock.now());
				const revoked = await boundaries.compare(checked.subject, madeAt, "sessions", skewMs);
				if (revoked === "revoked") {
					return { kind: "error", error: "invalid_grant", description: "assertion revoked" };
				}
				const { scope } = allowed;
				const { audience } = asked;
				const access = { subject: checked.subject, issuedTo: client.id, audience, scope };
				// Asked before the assertion is used up, so a refusal leaves it usable.
				const admitted = await admits(access);
				if (admitted.kind === "refused") return admitted;
				if (checked.expiresAt - c.clock.now() < 1000) return refusedGrant("expired");
				if ((await spend()) === "replayed")
					return { kind: "error", error: "invalid_grant", description: "assertion replayed" };
				// Cut to the assertion's end: one with less than a second left once signed, `tokens` refuses.
				const issued = await issue(access, { notAfter: checked.expiresAt });
				if (issued.kind === "refused") return issued;
				const token = issued.access;
				return {
					kind: "issued",
					body: {
						access_token: token.token,
						token_type: token.tokenType,
						expires_in: token.expiresIn,
						scope: scope.join(" "),
						// An ID-JAG's answer names the audience issued, however it was chosen.
						...(profile ? { resource: audience.length === 1 ? audience[0] : [...audience] } : {}),
					},
				};
			};
			/**
			 * A delegated issuer's assertion: checked and used up by its delegate alone, never another way. A
			 * public client proves the key it names; one with accept-unbound need not where it names none.
			 */
			const delegated = async (
				input: GrantInput,
				delegate: DelegatedAssertions,
				assertion: string,
			): Promise<GrantOutcome | Refused> => {
				// An entry's client takes its own entry's assertions alone: its delegate is never asked.
				if (binding.forAnother(undefined, input.client.id)) return anotherClient;
				const told = await checkedBy(delegate, assertion);
				// As an unknown signer is: the answer tells nothing of which issuers are delegated.
				if (told.kind === "invalid") return refusedGrant("untrusted signer");
				// A delegate may take one within its clock allowance past its end: a token needs a second left.
				if (told.expiresAt - c.clock.now() < 1000) return refusedGrant("expired");
				const { client } = input;
				if (!told.clients.includes(client.id))
					return refusedGrant("assertion is for another client");
				// A key it names is proved always: leaving out the proof never skips it.
				const unbound = told.holderDigest === undefined && acceptsUnbound(client);
				if (
					client.kind !== "confidential" &&
					!unbound &&
					!holds(input.binding, told.holderDigest)
				) {
					return refusedGrant("the request does not prove the key the assertion names");
				}
				const outcome = await issueFor(input, told, () => spentBy(delegate, assertion), []);
				if (client.kind !== "confidential" && unbound && outcome.kind === "issued") {
					c.log.warn("jwt-bearer.accept_unbound", { client: client.id });
				}
				return outcome;
			};
			return {
				grantType: jwtBearerGrantType,
				readsAmbient: "none",
				targets: true,
				...(c.section.issuers.some((i) => i.client !== undefined)
					? {
							// A request naming no client: the client of the entry whose verified assertion it carries.
							identify: async ({ param }) => {
								const assertion = param("assertion");
								if (!assertion) return assertionRequired;
								const sorted = sortedOut(assertion);
								if (sorted) return sorted;
								// A delegated issuer's identifies none: its delegate checks it for a client named.
								if (delegation.by.has(sentIssuerOf(assertion) ?? "")) return unidentified;
								return identifiedBy(await verify(assertion), (iss) => entries.get(iss), subjectOf);
							},
						}
					: {}),
				handle: async (input) => {
					const assertion = input.param("assertion");
					if (!assertion) return assertionRequired;
					const sorted = sortedOut(assertion);
					if (sorted) return sorted;
					// A delegated issuer's assertion goes its delegate's way alone, whatever it answers.
					const delegate = delegation.by.get(sentIssuerOf(assertion) ?? "");
					if (delegate) return delegated(input, delegate, assertion);
					// What identify found for a request naming no client, taken as it is: not checked again.
					const known = identifiedOf(input.identified);
					const verified = known ? known.verified : await verify(assertion);
					if (verified.kind === "invalid") return refusedGrant(verified.reason);
					const entry = entries.get(verified.entry) as IssuerEntry;
					// Bound to its client first, then held to its conditions, before any subject is looked up or jti spent.
					if (binding.forAnother(entry, input.client.id)) return anotherClient;
					// An ID-JAG, read by its profile's rules, is bound here too: the client it names, the key it names.
					let idJag: IdJag | undefined;
					if (entry.profile === "id-jag") {
						const told = read(verified);
						if (told.kind === "invalid") return refusedGrant(told.reason);
						const admitted = admit(told, { client: input.client, binding: input.binding });
						if (admitted.kind === "invalid") return refusedGrant(admitted.reason);
						idJag = told;
					}
					let subject = known?.subject;
					if (subject === undefined) {
						if (entry.conditions && !meets(entry.conditions, verified.claims))
							return refusedGrant("assertion does not meet its issuer's conditions");
						subject = await subjectOf(verified.entry, verified.subject);
						if (subject === undefined) return refusedGrant("unknown subject");
					}
					const checked = { ...verified, subject };
					const keepUntil = keepUntilOf(checked.expiresAt);
					// An issuer with a ledger uses its jti up there alone, never the store, whatever it answers;
					// the store keeps it by the `iss` as sent, so a self-issued signer's assertions are apart from its issuer's own.
					const ledger = ledgers.get(checked.entry);
					const spend = async () => {
						const told = ledger
							? await spentIn(ledger, {
									sentIssuer: checked.sentIssuer,
									jti: checked.jti,
									expiresAt: checked.expiresAt,
									keepUntil,
								})
							: // Relative, since the store judges a lifetime by its own clock.
								await spent.save(
									spentName(checked.sentIssuer, checked.jti),
									keepUntil - c.clock.now(),
								);
						return told === "replayed" || told === "exists" ? "replayed" : "spent";
					};
					return issueFor(input, checked, spend, ceilingsOf(entry), idJag);
				},
			};
		}),
	],
);
