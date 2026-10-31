import { clientAllowance } from "@mod/client-allowance";
import { clients } from "@mod/clients";
import { type ExternalJwt, externalJwt, type Policy } from "@mod/external-jwt";
import { withinHosts } from "@mod/host-entries";
import { type BuildContext, type Refusal, setting } from "@mod/kernel";
import { publicPem } from "@mod/keys";
import { z } from "zod";
import { conditionsSetting } from "../conditions/conditions.ts";
import {
	type DelegatedAssertions,
	delegatedAssertions,
	type JtiLedger,
	jtiLedgers,
	type SignerAlgorithm,
	type SignerKeys,
	signerKeys,
	takenAlgorithms,
} from "../contract.ts";
import { contributedSigners, fetchedSigners, type Signers, writtenSigners } from "../signers.ts";

/** The issuer's host, the only one its key set is fetched from; none for an issuer that is no URL. */
const hostsOf = (issuer: string) => (URL.canParse(issuer) ? [new URL(issuer).hostname] : []);

/** A public key only: a private key written here refuses boot rather than being dropped later. */
const readable = (pem: string) => publicPem(pem) !== undefined;

/** How an issuer's assertion names the subject a token is for. */
const subjectOf = {
	subject: z
		.enum(["as-is", "linked"])
		// Required, but checked past the union of key sources, so a refusal names this key.
		.optional()
		.describe(
			'Required. "as-is": the assertion\'s `sub` is the subject. "linked": the user `users` finds by the upstream identity (`upstream`, `sub`) is.',
		),
	upstream: z
		.string()
		.min(1)
		.optional()
		.describe('The IdP name `users` knows this issuer\'s signers by; written with "linked" only.'),
	"subject-is-key-thumbprint": z
		.boolean()
		.prefault(false)
		.describe(
			"Whether `sub` must be the JWK thumbprint (RFC 7638, SHA-256) of the key that signed.",
		),
	"self-issued-prefix": z
		.string()
		.regex(/^[\x21-\x7e]{1,64}$/, "1 to 64 printable ASCII characters")
		.optional()
		.describe(
			"Takes self-issued signers too: an assertion whose `iss` and `sub` are both this prefix and its key's JWK thumbprint, read as this issuer's. Needs `subject-is-key-thumbprint` and keys contributed.",
		),
};

const taken = z.enum(takenAlgorithms as [SignerAlgorithm, ...SignerAlgorithm[]]);
const listed = z.array(z.string().min(1)).min(1);

/** What an entry narrows of the section's policy. */
const narrowing = {
	conditions: conditionsSetting.optional(),
	"accept-any-subject": z
		.boolean()
		.prefault(false)
		.describe(
			"Takes any signer of an issuer whose every signer becomes a subject, with no conditions. Warned at boot.",
		),
	ceiling: z
		.strictObject({ scopes: listed.optional(), audiences: listed.optional() })
		.refine((c) => c.scopes !== undefined || c.audiences !== undefined, "names no list")
		.optional()
		.describe(
			"A ceiling over what this issuer's assertions are issued, within the client's allowance: `scopes`, `audiences`, each a list not empty.",
		),
	"max-assertion-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(1).max(86_400))
		.optional()
		.describe(
			"How far ahead its `exp` this issuer's assertion may be when it is taken, and how far its `exp` may be from its `iat`, no longer than the section's.",
		),
	"clock-skew": setting
		.duration("s")
		.pipe(z.number().int().min(0).max(300))
		.optional()
		.describe(
			"This issuer's clock allowance for what is taken, no wider than the section's; a revocation keeps the section's.",
		),
	profile: z
		.enum(["rfc7523", "id-jag"])
		.prefault("rfc7523")
		.describe(
			'The rules its assertions are taken by: "rfc7523", or "id-jag" (preview, draft-ietf-oauth-identity-assertion-authz-grant-04), each ID-JAG presented by the confidential client it names, within its scope and resources.',
		),
	client: z
		.string()
		.min(1)
		.optional()
		.describe(
			"The registered client this issuer's assertions identify where a request names none: public with method `none`, allowed this grant alone, no other entry's. Warned at boot.",
		),
};

/** The algorithms keys not written with theirs are taken under. */
const takes = {
	algorithms: z
		.array(taken)
		.min(1)
		.optional()
		.describe(
			"The algorithms this issuer's keys are taken under, by default EdDSA, ES256 and RS256.",
		),
};

const issuerEntry = z
	.union([
		z.strictObject({
			issuer: z.string().min(1),
			keys: z
				.array(
					z.strictObject({
						kid: z.string().min(1).optional(),
						alg: taken,
						"public-key": z
							.string()
							.refine(readable, "not readable as a public key PEM (a private key is refused)"),
					}),
				)
				.min(1),
			...subjectOf,
			...narrowing,
		}),
		z
			.strictObject({
				issuer: z.string().min(1),
				"jwks-uri": z.string(),
				"accept-key-set-elsewhere": z
					.boolean()
					.prefault(false)
					.describe("Takes a key set off the issuer's host, at https still. Warned at boot."),
				...subjectOf,
				...narrowing,
				...takes,
			})
			.refine(
				(i) =>
					URL.canParse(i["jwks-uri"]) &&
					new URL(i["jwks-uri"]).protocol === "https:" &&
					(i["accept-key-set-elsewhere"] || withinHosts(i["jwks-uri"], hostsOf(i.issuer))),
				"the key set is not at https on the issuer's host",
			)
			.refine(
				(i) => !i["subject-is-key-thumbprint"],
				"a key set fetched here cannot tell which key signed: subject-is-key-thumbprint needs keys written or contributed",
			),
		z.strictObject({ issuer: z.string().min(1), ...subjectOf, ...narrowing, ...takes }),
	])
	.refine((i) => i.subject !== undefined, {
		message: 'required: "as-is" or "linked"',
		path: ["subject"],
	})
	.refine((i) => (i.subject === "linked") === (i.upstream !== undefined), {
		message: 'upstream is written with subject = "linked", and only then',
		path: ["upstream"],
	})
	.refine(
		(i) =>
			i["self-issued-prefix"] === undefined ||
			(i["subject-is-key-thumbprint"] && !("keys" in i) && !("jwks-uri" in i)),
		{
			message: "a self-issued prefix needs subject-is-key-thumbprint and keys contributed",
			path: ["self-issued-prefix"],
		},
	)
	// An ID-JAG's `sub` is a user, never its signer's key; and its client authenticates and is named.
	.refine((i) => i.profile !== "id-jag" || !i["subject-is-key-thumbprint"], {
		message: "an ID-JAG's subject is a user: not written beside subject-is-key-thumbprint",
		path: ["profile"],
	})
	.refine((i) => i.profile !== "id-jag" || i["self-issued-prefix"] === undefined, {
		message: "an ID-JAG's signer is its IdP: not written beside self-issued-prefix",
		path: ["profile"],
	})
	.refine((i) => i.profile !== "id-jag" || i.client === undefined, {
		message:
			"an ID-JAG is presented by the confidential client it names: not written beside client",
		path: ["profile"],
	});

/** One trusted issuer, as the section gives it. */
export type IssuerEntry = z.output<typeof issuerEntry>;

/** The section's `issuers`. */
export const issuersSetting = z
	.array(issuerEntry)
	.prefault([])
	.describe(
		"The trusted issuers: each with its public keys (kid, alg, SPKI PEM), its key set's URL at https on its host, or neither, its keys then contributed at `signerKeys`. An entry's keys are `issuer`; `keys`, or `jwks-uri` with `accept-key-set-elsewhere`, or neither; `subject`, `upstream`, `subject-is-key-thumbprint`, `self-issued-prefix`, `conditions`, `accept-any-subject`, `ceiling`, `max-assertion-lifetime`, `clock-skew`, `profile` and `client`; and `algorithms`, which only an entry without `keys` takes; `jwt-bearer`'s internal module `issuers` says what each takes.",
	);

/** A trusted issuer that takes self-issued signers: the prefix of their names, and its place. */
export interface SelfIssuedEntry {
	readonly prefix: string;
	readonly issuer: string;
	readonly where: string;
}

/** The entries that take self-issued signers, in the settings' order. */
export const selfIssuedOf = (issuers: readonly IssuerEntry[]): readonly SelfIssuedEntry[] =>
	issuers.flatMap((i, at) => {
		const prefix = i["self-issued-prefix"];
		return prefix === undefined
			? []
			: [{ prefix, issuer: i.issuer, where: `jwt-bearer.issuers.${at}` }];
	});

/** Refusals of prefixes that could read one assertion as two issuers', each at its place, whatever the order. */
function prefixRefusals(issuers: readonly IssuerEntry[]) {
	const refused: Refusal[] = [];
	for (const own of selfIssuedOf(issuers)) {
		const where = `${own.where}.self-issued-prefix`;
		for (const [b, other] of issuers.entries()) {
			if (other.issuer.startsWith(own.prefix)) {
				refused.push({ where, reason: `starts the issuer of jwt-bearer.issuers.${b}` });
			}
		}
		for (const theirs of selfIssuedOf(issuers)) {
			if (
				theirs.where !== own.where &&
				(theirs.prefix.startsWith(own.prefix) || own.prefix.startsWith(theirs.prefix))
			) {
				refused.push({ where, reason: `overlaps the self-issued prefix of ${theirs.where}` });
			}
		}
	}
	return refused;
}

/** Each linked issuer, by the IdP name its signers are known by. */
export const linkedOf = (issuers: readonly IssuerEntry[]): ReadonlyMap<string, string> =>
	new Map(issuers.flatMap((i) => (i.upstream ? [[i.issuer, i.upstream] as const] : [])));

/** The trusted issuers' signers and ledgers, or why boot is refused. */
export type Trust =
	| {
			readonly kind: "trusted";
			readonly trusted: ReadonlyMap<string, Signers>;
			readonly ledgers: ReadonlyMap<string, JtiLedger>;
			/** What boot warns of, each at its place. */
			readonly warnings: readonly { readonly event: string; readonly where: string }[];
	  }
	| { readonly kind: "refused"; readonly refusals: readonly Refusal[] };

/** A registered client, as an entry's `client` is held to it. */
export interface RegisteredClient {
	readonly id: string;
	/** Public with method `none`: nothing it authenticates with. */
	readonly credentialless: boolean;
	/** Allowed this grant, and no other. */
	readonly thisGrantAlone: boolean;
}

/** Each issuer's signers, from its written keys, its key set or the keys contributed for it. */
export async function trustedWith(p: {
	readonly jwt: ExternalJwt;
	readonly issuers: readonly IssuerEntry[];
	/** The section's lifetime and clock skew (seconds), which an entry may narrow alone. */
	readonly section: { readonly "max-assertion-lifetime": number; readonly "clock-skew": number };
	readonly contributed: readonly SignerKeys[];
	readonly ledgers: readonly JtiLedger[];
	/** The registered clients, which an entry's `client` names. */
	readonly clients: readonly RegisteredClient[];
	readonly policyOf: (entry: IssuerEntry) => Policy;
}): Promise<Trust> {
	const contributed = new Map(p.contributed.map((k) => [k.issuer, k]));
	const trusted = new Map<string, Signers>();
	// Named by its place in the settings, never by its value: a refusal tells no setting's value.
	const refused: Refusal[] = [];
	const warnings: { event: string; where: string }[] = [];
	const firstAt = new Map<string, number>();
	const clientAt = new Map<string, number>();
	for (const [at, i] of p.issuers.entries()) {
		const where = `jwt-bearer.issuers.${at}`;
		const lifetime = i["max-assertion-lifetime"];
		if (lifetime !== undefined && lifetime > p.section["max-assertion-lifetime"]) {
			refused.push({
				where: `${where}.max-assertion-lifetime`,
				reason: "is longer than the section's",
			});
		}
		const skew = i["clock-skew"];
		if (skew !== undefined && skew > p.section["clock-skew"]) {
			refused.push({ where: `${where}.clock-skew`, reason: "is wider than the section's" });
		}
		const first = firstAt.get(i.issuer);
		if (first === undefined) firstAt.set(i.issuer, at);
		else refused.push({ where, reason: `names the same issuer as jwt-bearer.issuers.${first}` });
		const keys = contributed.get(i.issuer);
		const written = "keys" in i || "jwks-uri" in i;
		if (written && keys) refused.push({ where, reason: "has its keys written and contributed" });
		if (!written && !keys) refused.push({ where, reason: "has no keys written or contributed" });
		const thumbprint = i["subject-is-key-thumbprint"];
		refused.push(...anySubjectRefusals(i, where, keys));
		if (i["accept-any-subject"] && !i.conditions)
			warnings.push({ event: "jwt-bearer.any_subject", where });
		if (i.client !== undefined) {
			refused.push(...clientRefusals(i.client, at, p.clients, clientAt));
			warnings.push({ event: "jwt-bearer.clientless_issuer", where });
		}
		trusted.set(
			i.issuer,
			"keys" in i
				? await writtenSigners(
						p.jwt,
						i.keys.map(({ kid, alg, "public-key": pem }) => ({
							alg,
							pem,
							...(kid ? { kid } : {}),
						})),
						p.policyOf(i),
						thumbprint,
					)
				: "jwks-uri" in i
					? fetchedSigners(p.jwt, keySetOf(i), p.policyOf(i))
					: contributedSigners(p.jwt, keys as NonNullable<typeof keys>, p.policyOf(i), thumbprint),
		);
		if ("jwks-uri" in i && i["accept-key-set-elsewhere"]) {
			warnings.push({ event: "jwt-bearer.key_set_elsewhere", where });
		}
	}
	refused.push(...prefixRefusals(p.issuers));
	const ledgers = new Map(p.ledgers.map((l) => [l.issuer, l]));
	for (const [what, named] of [
		["keys are", [...contributed.keys()]],
		["jti ledgers are", [...ledgers.keys()]],
	] as const) {
		const unnamed = named.filter((name) => !trusted.has(name)).length;
		if (unnamed > 0) {
			refused.push({
				where: "jwt-bearer.issuers",
				reason: `${what} contributed for ${unnamed} issuer${unnamed === 1 ? "" : "s"} none of these names: name ${unnamed === 1 ? "it" : "them"} here, or leave out the module that contributes them`,
			});
		}
	}
	if (refused.length > 0) return { kind: "refused", refusals: refused };
	return { kind: "trusted", trusted, ledgers, warnings };
}

/**
 * An issuer whose every signer becomes a subject (as-is, no thumbprint, its keys the issuer's whole:
 * written, a key set, or contributed without the promise of answering each signer's own alone) is
 * held to conditions, or to accept-any-subject, and accept-any-subject to such an issuer alone.
 */
function anySubjectRefusals(
	i: IssuerEntry,
	where: string,
	keys: SignerKeys | undefined,
): Refusal[] {
	const accepted = i["accept-any-subject"];
	const whole = "keys" in i || "jwks-uri" in i || (keys !== undefined && keys.perSigner !== true);
	const anySigner = i.subject === "as-is" && !i["subject-is-key-thumbprint"] && whole;
	const at = `${where}.accept-any-subject`;
	// A request naming no client has no authentication: conditions, a table or keys narrow it alone.
	if (accepted && i.client !== undefined)
		return [{ where: at, reason: "is written beside client" }];
	if (accepted && i.conditions) return [{ where: at, reason: "is written beside conditions" }];
	if (accepted && !anySigner)
		return [{ where: at, reason: "is for an issuer whose every signer becomes a subject" }];
	if (anySigner && !accepted && !i.conditions) {
		return [
			{
				where,
				reason:
					"an issuer whose every signer becomes a subject needs conditions, or accept-any-subject",
			},
		];
	}
	return [];
}

/**
 * An entry's client: registered with nothing it authenticates with, allowed this grant alone and no
 * other entry's, so a request naming none skips no client's authentication and opens no other grant.
 */
function clientRefusals(
	id: string,
	at: number,
	registered: readonly RegisteredClient[],
	firstAt: Map<string, number>,
): Refusal[] {
	const where = `jwt-bearer.issuers.${at}.client`;
	const first = firstAt.get(id);
	if (first !== undefined) {
		return [{ where, reason: `names the same client as jwt-bearer.issuers.${first}` }];
	}
	firstAt.set(id, at);
	const found = registered.find((k) => k.id === id);
	if (found === undefined) return [{ where, reason: "names no registered client" }];
	if (!found.credentialless) {
		return [
			{ where, reason: "names a client with credentials: it needs to be public with method none" },
		];
	}
	if (!found.thisGrantAlone) {
		return [{ where, reason: "names a client allowed another grant than this one" }];
	}
	return [];
}

/** Where an entry's key set is fetched from: its URL, from the issuer's host, or its own where accepted. */
const keySetOf = (i: Extract<IssuerEntry, { readonly "jwks-uri": string }>) => ({
	url: i["jwks-uri"],
	hosts: i["accept-key-set-elsewhere"] ? [new URL(i["jwks-uri"]).hostname] : hostsOf(i.issuer),
});

/** What `issuersIn` takes from the build context. */
export const issuersTakes = [externalJwt, signerKeys, jtiLedgers, clients] as const;

/** The trusted issuers, their keys and ledgers taken from the composition. */
export async function issuersIn(
	c: Pick<BuildContext<unknown>, "get" | "collect" | "log">,
	section: Parameters<typeof trustedWith>[0]["section"] & {
		readonly issuers: readonly IssuerEntry[];
	},
	policyOf: (entry: IssuerEntry) => Policy,
	/** This grant's type, the one an entry's client may be allowed. */
	grantType: string,
): Promise<Trust> {
	const registered = (await c.get(clients)).registered().map((k) => {
		const allowed = clientAllowance.grantsOf(k);
		return {
			id: k.id,
			credentialless: k.kind === "public" && k.method === "none",
			thisGrantAlone: allowed.length > 0 && allowed.every((g) => g === grantType),
		};
	});
	const trust = await trustedWith({
		jwt: await c.get(externalJwt),
		issuers: section.issuers,
		section,
		contributed: await c.collect(signerKeys),
		ledgers: await c.collect(jtiLedgers),
		clients: registered,
		policyOf,
	});
	// Told once each boot, by place: the operator's values are never written out.
	if (trust.kind === "trusted") {
		for (const w of trust.warnings) c.log.warn(w.event, { key: w.where });
		const selfIssued = selfIssuedOf(section.issuers);
		if (selfIssued.length > 0) {
			c.log.warn("jwt-bearer.self_issued_signers", {
				key: selfIssued.map((s) => s.where).join(","),
			});
		}
	}
	return trust;
}

/** The section's `delegated-issuers`. */
export const delegatedSetting = z
	.array(z.string().min(1))
	.prefault([])
	.describe(
		"Issuers whose assertions another module checks by its own rules, each exactly as sent: their audience is an app, not this server, so RFC 7523 §3 does not hold. Each needs the one module that checks it.",
	);

/** The delegate of each delegated issuer, or why boot is refused. */
export type Delegation =
	| { readonly kind: "delegated"; readonly by: ReadonlyMap<string, DelegatedAssertions> }
	| { readonly kind: "refused"; readonly refusals: readonly Refusal[] };

/**
 * Each delegated issuer's one delegate. An issuer another way reads too, the issuer of an entry or one
 * a self-issued prefix starts, is refused, so no assertion is read by two rules (RFC 8725 §3.12).
 */
export function delegatedWith(p: {
	readonly issuers: readonly IssuerEntry[];
	readonly delegated: readonly string[];
	readonly contributed: readonly DelegatedAssertions[];
}): Delegation {
	const refused: Refusal[] = [];
	const by = new Map<string, DelegatedAssertions>();
	const firstAt = new Map<string, number>();
	for (const [at, iss] of p.delegated.entries()) {
		const where = `jwt-bearer.delegated-issuers.${at}`;
		const first = firstAt.get(iss);
		if (first !== undefined) {
			refused.push({
				where,
				reason: `names the same issuer as jwt-bearer.delegated-issuers.${first}`,
			});
			continue;
		}
		firstAt.set(iss, at);
		for (const [b, entry] of p.issuers.entries()) {
			if (entry.issuer === iss) {
				refused.push({ where, reason: `is the issuer of jwt-bearer.issuers.${b}` });
			}
			// Stricter than reading a self-issued signer, which also needs a thumbprint after the prefix.
			const prefix = entry["self-issued-prefix"];
			if (prefix !== undefined && iss.startsWith(prefix)) {
				refused.push({
					where,
					reason: `starts with the self-issued prefix of jwt-bearer.issuers.${b}`,
				});
			}
		}
		const checking = p.contributed.filter((d) => d.issuers.includes(iss));
		const [one] = checking;
		if (one === undefined)
			refused.push({ where, reason: "no module checks this issuer's assertions" });
		else if (checking.length > 1) {
			const names = checking.map((d) => d.declaredBy).join(", ");
			refused.push({
				where,
				reason: `more than one module checks this issuer's assertions: ${names}`,
			});
		} else by.set(iss, one);
	}
	const unnamed = new Set(p.contributed.flatMap((d) => d.issuers).filter((i) => !firstAt.has(i)))
		.size;
	if (unnamed > 0) {
		refused.push({
			where: "jwt-bearer.delegated-issuers",
			reason: `assertions are delegated for ${unnamed} issuer${unnamed === 1 ? "" : "s"} none of these names: name ${unnamed === 1 ? "it" : "them"} here, or leave out the module that contributes them`,
		});
	}
	return refused.length > 0 ? { kind: "refused", refusals: refused } : { kind: "delegated", by };
}

/** The delegated issuers' delegates, taken from the composition. */
export async function delegatedIn(
	c: Pick<BuildContext<unknown>, "collect">,
	issuers: readonly IssuerEntry[],
	delegated: readonly string[],
): Promise<Delegation> {
	return delegatedWith({ issuers, delegated, contributed: await c.collect(delegatedAssertions) });
}

/** What `delegatedIn` takes from the build context. */
export const delegatedTakes = [delegatedAssertions] as const;
