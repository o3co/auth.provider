import type { Client } from "@mod/clients";
import { deepFreeze } from "@mod/kernel";
import { type Allowances, allowances } from "./metadata.ts";

/** The lists a client's allowances name. */
export interface AllowanceLists {
	readonly grants: readonly string[];
	readonly scopes: readonly string[];
	readonly audiences: readonly string[];
}

/** A ceiling over an issuance: a list it holds narrows it, a list it leaves out does not; an empty list allows nothing. */
export interface Ceiling {
	readonly scopes?: readonly string[];
	readonly audiences?: readonly string[];
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
	 * As `allowedIssuance`, within every ceiling given as well as the client's allowance: the scopes,
	 * its defaults among them, and the audiences, the issuer's for a client allowed none, are narrowed
	 * to what each ceiling holds. A default the ceilings leave none of is refused, never issued empty;
	 * no audience left is `invalid_target`. With no ceiling it is `allowedIssuance`.
	 */
	allowedIssuanceWithin(
		client: Client,
		ceilings: readonly Ceiling[],
		requested: string | undefined,
		issuer: string,
	):
		| {
				readonly kind: "allowed";
				readonly scope: readonly string[];
				readonly audience: readonly string[];
		  }
		| {
				readonly kind: "error";
				readonly error: "invalid_scope" | "invalid_target";
				readonly description?: string;
		  };
	/** As `allowsAudience`, within every ceiling given as well. */
	allowsAudienceWithin(
		client: Client,
		ceilings: readonly Ceiling[],
		audience: string,
		issuer: string,
	): boolean;
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

/** What every ceiling that holds such a list keeps of the values. */
const narrowed = (
	values: readonly string[],
	ceilings: readonly Ceiling[],
	name: keyof Ceiling,
): readonly string[] =>
	ceilings.reduce<readonly string[]>((kept, c) => {
		const held = c[name];
		return held === undefined ? kept : kept.filter((v) => held.includes(v));
	}, values);

const allowedIssuance: ClientAllowance["allowedIssuance"] = (client, requested, issuer) => {
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
};

const allowedIssuanceWithin: ClientAllowance["allowedIssuanceWithin"] = (
	client,
	ceilings,
	requested,
	issuer,
) => {
	if (ceilings.length === 0) return allowedIssuance(client, requested, issuer);
	const allowed = client.section(allowances);
	const scopes = narrowed(allowed.scopes, ceilings, "scopes");
	const defaults = allowed["default-scopes"];
	const kept = defaults === undefined ? undefined : narrowed(defaults, ceilings, "scopes");
	const named = parseScope(requested);
	const omitted = named?.length === 0;
	// A client that must name a scope still must, by its own allowance whatever the ceilings keep of
	// it; a default the ceilings take all of is refused as no default would be, never issued empty.
	const lost = defaults !== undefined && defaults.length > 0 && kept?.length === 0;
	if (omitted && (lost || (kept === undefined && allowed.scopes.length > 0))) {
		return scopes.length > 0
			? { kind: "error", error: "invalid_scope", description: "scope is required" }
			: { kind: "error", error: "invalid_scope" };
	}
	const asked = omitted ? (kept ?? []) : named;
	if (!asked || asked.some((s) => !scopes.includes(s))) {
		return { kind: "error", error: "invalid_scope" };
	}
	const audiences = narrowed(audiencesOf(allowed, issuer), ceilings, "audiences");
	if (audiences.length === 0) {
		return { kind: "error", error: "invalid_target", description: "no audience is within reach" };
	}
	return { kind: "allowed", scope: [...new Set(asked)], audience: audiences.slice(0, 1) };
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
	allowedIssuance,
	allowedIssuanceWithin,
	allowsAudienceWithin: (client, ceilings, audience, issuer) =>
		narrowed(audiencesOf(client.section(allowances), issuer), ceilings, "audiences").includes(
			audience,
		),
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
