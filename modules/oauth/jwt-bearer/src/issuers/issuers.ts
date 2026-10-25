import { type ExternalJwt, externalJwt, type Policy } from "@mod/external-jwt";
import type { BuildContext, Refusal } from "@mod/kernel";
import { publicPem } from "@mod/keys";
import { withinHosts } from "@mod/outbound-policy";
import { z } from "zod";
import {
	algorithms,
	type JtiLedger,
	jtiLedgers,
	type SignerKeys,
	signerKeys,
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
};

const issuerEntry = z
	.union([
		z.strictObject({
			issuer: z.string().min(1),
			keys: z
				.array(
					z.strictObject({
						kid: z.string().min(1).optional(),
						alg: z.enum(algorithms),
						"public-key": z
							.string()
							.refine(readable, "not readable as a public key PEM (a private key is refused)"),
					}),
				)
				.min(1),
			...subjectOf,
		}),
		z
			.strictObject({ issuer: z.string().min(1), "jwks-uri": z.string(), ...subjectOf })
			.refine(
				(i) =>
					withinHosts(i["jwks-uri"], hostsOf(i.issuer)) &&
					new URL(i["jwks-uri"]).protocol === "https:",
				"the key set is not at https on the issuer's host",
			)
			.refine(
				(i) => !i["subject-is-key-thumbprint"],
				"a key set fetched here cannot tell which key signed: subject-is-key-thumbprint needs keys written or contributed",
			),
		z.strictObject({ issuer: z.string().min(1), ...subjectOf }),
	])
	.refine((i) => i.subject !== undefined, {
		message: 'required: "as-is" or "linked"',
		path: ["subject"],
	})
	.refine((i) => (i.subject === "linked") === (i.upstream !== undefined), {
		message: 'upstream is written with subject = "linked", and only then',
		path: ["upstream"],
	});

/** One trusted issuer, as the section gives it. */
export type IssuerEntry = z.output<typeof issuerEntry>;

/** The section's `issuers`. */
export const issuersSetting = z
	.array(issuerEntry)
	.prefault([])
	.describe(
		"The trusted issuers: each with its public keys (kid, alg, SPKI PEM), its key set's URL at https on its host, or neither, its keys then contributed at `signerKeys`.",
	);

/** Each linked issuer, by the IdP name its signers are known by. */
export const linkedOf = (issuers: readonly IssuerEntry[]): ReadonlyMap<string, string> =>
	new Map(issuers.flatMap((i) => (i.upstream ? [[i.issuer, i.upstream] as const] : [])));

/** The trusted issuers' signers and ledgers, or why boot is refused. */
export type Trust =
	| {
			readonly kind: "trusted";
			readonly trusted: ReadonlyMap<string, Signers>;
			readonly ledgers: ReadonlyMap<string, JtiLedger>;
	  }
	| { readonly kind: "refused"; readonly refusals: readonly Refusal[] };

/** Each issuer's signers, from its written keys, its key set or the keys contributed for it. */
export async function trustedWith(p: {
	readonly jwt: ExternalJwt;
	readonly issuers: readonly IssuerEntry[];
	readonly contributed: readonly SignerKeys[];
	readonly ledgers: readonly JtiLedger[];
	readonly policyOf: (entry: IssuerEntry) => Policy;
}): Promise<Trust> {
	const contributed = new Map(p.contributed.map((k) => [k.issuer, k]));
	const trusted = new Map<string, Signers>();
	// Named by its place in the settings, never by its value: a refusal tells no setting's value.
	const refused: Refusal[] = [];
	const firstAt = new Map<string, number>();
	for (const [at, i] of p.issuers.entries()) {
		const where = `jwt-bearer.issuers.${at}`;
		const first = firstAt.get(i.issuer);
		if (first === undefined) firstAt.set(i.issuer, at);
		else refused.push({ where, reason: `names the same issuer as jwt-bearer.issuers.${first}` });
		const keys = contributed.get(i.issuer);
		const written = "keys" in i || "jwks-uri" in i;
		if (written && keys) refused.push({ where, reason: "has its keys written and contributed" });
		if (!written && !keys) refused.push({ where, reason: "has no keys written or contributed" });
		const thumbprint = i["subject-is-key-thumbprint"];
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
					? fetchedSigners(p.jwt, { url: i["jwks-uri"], hosts: hostsOf(i.issuer) }, p.policyOf(i))
					: contributedSigners(p.jwt, keys as NonNullable<typeof keys>, p.policyOf(i), thumbprint),
		);
	}
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
	return { kind: "trusted", trusted, ledgers };
}

/** What `issuersIn` takes from the build context. */
export const issuersTakes = [externalJwt, signerKeys, jtiLedgers] as const;

/** The trusted issuers, their keys and ledgers taken from the composition. */
export async function issuersIn(
	c: Pick<BuildContext<unknown>, "get" | "collect">,
	issuers: readonly IssuerEntry[],
	policyOf: (entry: IssuerEntry) => Policy,
): Promise<Trust> {
	return trustedWith({
		jwt: await c.get(externalJwt),
		issuers,
		contributed: await c.collect(signerKeys),
		ledgers: await c.collect(jtiLedgers),
		policyOf,
	});
}
