import type { Client } from "@mod/clients";
import { deepFreeze } from "@mod/kernel";
import { type Allowances, allowances } from "./metadata.ts";

/** The lists a client's allowances name. */
export interface AllowanceLists {
	readonly grants: readonly string[];
	readonly scopes: readonly string[];
	readonly audiences: readonly string[];
}

/** The scope and audience of an issuance. */
export interface Issued {
	readonly scope: readonly string[];
	readonly audience: readonly string[];
}

/** What a client may be issued and may see, decided over its `client-allowance` section. */
export interface ClientAllowance {
	allowsGrant(client: Client, grantType: string): boolean;
	/** The grant types a client is allowed, as its allowance lists them. */
	grantsOf(client: Client): readonly string[];
	/** Whether a client may be issued this one scope. */
	allowsScope(client: Client, scope: string): boolean;
	/** Whether an earlier issuance is within the allowance now: each scope, and exactly one audience it may be issued. */
	covers(client: Client, issued: Issued, issuer: string): boolean;
	/** Whether an audience may be issued: one of the allowed audiences, or the issuer if none is. */
	allowsAudience(client: Client, audience: string, issuer: string): boolean;
	maySee(client: Client, audience: readonly string[]): boolean;
	/**
	 * The scope and audience a client may be issued for a requested scope: its defaults when none is
	 * asked (an explicitly empty default issues no scope; no default at all is refused while scopes
	 * are allowed), nothing outside its allowance, and its first allowed audience or else the issuer.
	 */
	allowedIssuance(
		client: Client,
		requested: string | undefined,
		issuer: string,
	):
		| {
				readonly kind: "allowed";
				readonly scope: readonly string[];
				readonly audience: readonly string[];
		  }
		| { readonly kind: "error"; readonly error: "invalid_scope"; readonly description?: string };
	/**
	 * The section entry (name to value) for a client asking within a ceiling: each list keeps what
	 * both hold, and a list not asked is the ceiling's. Undefined (refused) when the asked audiences
	 * leave none of a ceiling that names some, since no audiences would mean the issuer.
	 */
	allowancesWithin(
		ceiling: AllowanceLists,
		asked: Partial<AllowanceLists>,
	): Readonly<Record<string, unknown>> | undefined;
	/**
	 * RFC 6749 §3.3 scope tokens; none when the value is empty or left out (§3.2). Undefined when it
	 * is not scope tokens joined by single spaces.
	 */
	parseScope(raw: string | undefined): string[] | undefined;
}

/** The audiences a client may be issued: those it is allowed, or the issuer when it is allowed none. */
const audiencesOf = (allowed: Pick<Allowances, "audiences">, issuer: string): readonly string[] =>
	allowed.audiences.length > 0 ? allowed.audiences : [issuer];

const parseScope = (raw: string | undefined) => {
	if (raw === undefined || raw === "") return [];
	return /^[\x21\x23-\x5b\x5d-\x7e]+( [\x21\x23-\x5b\x5d-\x7e]+)*$/.test(raw)
		? raw.split(" ")
		: undefined;
};

const covers: ClientAllowance["covers"] = (client, issued, issuer) => {
	const allowed = client.section(allowances);
	return (
		issued.scope.every((s) => allowed.scopes.includes(s)) &&
		issued.audience.length === 1 &&
		audiencesOf(allowed, issuer).includes(issued.audience[0] as string)
	);
};

export const clientAllowance: ClientAllowance = Object.freeze({
	allowsGrant: (client, grantType) => client.section(allowances).grants.includes(grantType),
	grantsOf: (client) => client.section(allowances).grants,
	allowsScope: (client, scope) => client.section(allowances).scopes.includes(scope),
	covers,
	allowsAudience: (client, audience, issuer) =>
		audiencesOf(client.section(allowances), issuer).includes(audience),
	maySee: (client, audience) => {
		const visible = new Set([...client.section(allowances).audiences, client.id]);
		return audience.some((a) => visible.has(a));
	},
	allowedIssuance: (client, requested, issuer) => {
		const allowed = client.section(allowances);
		const defaults = allowed["default-scopes"];
		const named = parseScope(requested);
		const omitted = named?.length === 0;
		if (omitted && defaults === undefined && allowed.scopes.length > 0) {
			return { kind: "error", error: "invalid_scope", description: "scope is required" };
		}
		const asked = omitted ? (defaults ?? []) : named;
		if (!asked || asked.some((s) => !allowed.scopes.includes(s))) {
			return { kind: "error", error: "invalid_scope" };
		}
		return {
			kind: "allowed",
			scope: [...new Set(asked)],
			audience: audiencesOf(allowed, issuer).slice(0, 1),
		};
	},
	allowancesWithin: (ceiling, asked) => {
		const within = (name: keyof AllowanceLists) => [
			...new Set((asked[name] ?? ceiling[name]).filter((v) => ceiling[name].includes(v))),
		];
		const value = {
			grants: within("grants"),
			scopes: within("scopes"),
			audiences: within("audiences"),
		};
		// No audiences would mean the issuer, which a ceiling naming audiences does not allow.
		if (ceiling.audiences.length > 0 && value.audiences.length === 0) return undefined;
		return deepFreeze({ [allowances.name]: value });
	},
	parseScope,
} satisfies ClientAllowance);
