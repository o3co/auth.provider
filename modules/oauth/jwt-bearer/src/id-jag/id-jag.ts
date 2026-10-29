import { type Ceiling, clientAllowance } from "@mod/client-allowance";
import { typOf } from "@mod/external-jwt";
import type { GrantInput } from "@mod/grants";
import { resourceRefusal } from "@mod/resource-indicators";
import { decodeProtectedHeader } from "jose";

/** The `typ` of an ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant-04 §3.1), as `typOf` reads one. */
export const idJagTyp = "oauth-id-jag+jwt";

/** The profile's name in an authorization server's metadata (§7.2). */
export const idJagProfile = "urn:ietf:params:oauth:grant-profile:id-jag";

/** What a verified ID-JAG names: the client presenting it, and what its IdP allowed. */
export interface IdJag {
	readonly kind: "id-jag";
	readonly clientId: string;
	/** Its `scope`, where it says one. */
	readonly scope?: readonly string[];
	/** Its `resource`, one or more, where it says one. */
	readonly resources?: readonly string[];
	/** Its `cnf.jkt`: the DPoP key's thumbprint the request must prove. */
	readonly keyThumbprint?: string;
}

export type Invalid = { readonly kind: "invalid"; readonly reason: string };

/**
 * Whether an assertion's header, read unverified, names the ID-JAG's type: for sorting it before
 * anything is verified, never for taking it. One that is no JWT names none.
 */
export function namesIdJag(assertion: string): boolean {
	try {
		return typOf(decodeProtectedHeader(assertion)) === idJagTyp;
	} catch {
		return false;
	}
}

const invalid = (reason: string): Invalid => ({ kind: "invalid", reason });
const malformed = invalid("missing or malformed claims");

/** A claim of the claims' own, never one an object inherits. */
const own = (claims: Readonly<Record<string, unknown>>, name: string) =>
	Object.hasOwn(claims, name) ? claims[name] : undefined;
const isObject = (v: unknown): v is Record<string, unknown> =>
	typeof v === "object" && v !== null && !Array.isArray(v);
/** An absolute URI with no fragment, as RFC 8707 §2 asks of a resource, read as resource-indicators reads one. */
const isResource = (v: unknown): v is string =>
	typeof v === "string" && resourceRefusal(v) === undefined;
const isThumbprint = (v: unknown): v is string =>
	typeof v === "string" && /^[A-Za-z0-9_-]{43}$/.test(v);

/**
 * A verified ID-JAG's header and claims, read by the profile's rules, or why they are refused; its
 * signature, issuer, audience value, times and `jti` are checked before, by `assertion`.
 */
export function read(verified: {
	readonly header: Readonly<Record<string, unknown>>;
	readonly claims: Readonly<Record<string, unknown>>;
}): IdJag | Invalid {
	const { claims } = verified;
	// The signed header says it again: what was sorted unverified holds once verified.
	if (typOf(verified.header) !== idJagTyp) return invalid("untrusted signer");
	const aud = own(claims, "aud");
	if (Array.isArray(aud) && aud.length !== 1) return invalid("wrong audience");
	if (own(claims, "tenant") !== undefined || own(claims, "aud_tenant") !== undefined)
		return invalid("tenant not taken");
	const clientId = own(claims, "client_id");
	if (typeof own(claims, "iat") !== "number") return malformed;
	if (typeof clientId !== "string" || clientId.length < 1 || clientId.length > 255)
		return malformed;
	// A scope signed empty would read as none, and the client's defaults would stand in.
	const rawScope = own(claims, "scope");
	const scope =
		rawScope === undefined
			? undefined
			: typeof rawScope === "string" && rawScope !== ""
				? clientAllowance.parseScope(rawScope)
				: null;
	if (scope === null || (rawScope !== undefined && scope === undefined)) return malformed;
	const rawResource = own(claims, "resource");
	const resources =
		rawResource === undefined
			? undefined
			: Array.isArray(rawResource)
				? rawResource
				: [rawResource];
	if (resources && (resources.length === 0 || !resources.every(isResource))) return malformed;
	const cnf = own(claims, "cnf");
	if (cnf !== undefined) {
		if (!isObject(cnf) || Object.keys(cnf).join() !== "jkt" || !isThumbprint(cnf.jkt))
			return malformed;
	}
	const details = own(claims, "authorization_details");
	if (details !== undefined) {
		const formed =
			Array.isArray(details) &&
			details.every((d) => isObject(d) && typeof d.type === "string" && d.type !== "");
		if (!formed) return malformed;
		// No type is served: what the IdP allowed must be in a scope, else defaults would stand in for it.
		if (scope === undefined) return invalid("authorization details are not served");
	}
	const act = own(claims, "act");
	if (act !== undefined && !(isObject(act) && typeof act.sub === "string")) return malformed;
	return {
		kind: "id-jag",
		clientId,
		...(scope ? { scope } : {}),
		...(resources ? { resources: resources as string[] } : {}),
		...(isObject(cnf) ? { keyThumbprint: cnf.jkt as string } : {}),
	};
}

/**
 * Whether the request may present it: the confidential client it names, proving by DPoP the key it
 * names, if any. A binding is DPoP by its token type, as `delegated` tells one.
 */
export function admit(
	idJag: IdJag,
	request: { readonly client: GrantInput["client"]; readonly binding?: GrantInput["binding"] },
): { readonly kind: "admitted" } | Invalid {
	if (request.client.kind !== "confidential")
		return invalid("the profile needs a confidential client");
	if (idJag.clientId !== request.client.id) return invalid("assertion is for another client");
	if (idJag.keyThumbprint !== undefined) {
		const { binding } = request;
		if (binding?.tokenType !== "DPoP" || binding.confirmation !== idJag.keyThumbprint)
			return invalid("the request does not prove the key the assertion names");
	}
	return { kind: "admitted" };
}

/**
 * The scope asked: the request's own where it names one, else the ID-JAG's; and the ceiling the
 * ID-JAG holds the issuance to, beside its issuer's and the client's allowance.
 */
export function asked(
	idJag: IdJag,
	requested: string | undefined,
): { readonly scope: string | undefined; readonly ceiling: Ceiling } {
	const scope = requested !== undefined && requested !== "" ? requested : idJag.scope?.join(" ");
	return {
		scope,
		ceiling: {
			...(idJag.scope ? { scopes: idJag.scope } : {}),
			...(idJag.resources ? { audiences: idJag.resources } : {}),
		},
	};
}

/** What is about to be issued, checked again against the ID-JAG: a second guard over the ceiling. */
export function recheck(
	idJag: IdJag,
	issued: { readonly scope: readonly string[]; readonly audience: readonly string[] },
):
	| { readonly kind: "ok" }
	| { readonly kind: "error"; readonly error: "invalid_scope" | "invalid_target" } {
	const { scope, resources } = idJag;
	if (scope && !issued.scope.every((s) => scope.includes(s)))
		return { kind: "error", error: "invalid_scope" };
	if (resources && !issued.audience.every((a) => resources.includes(a)))
		return { kind: "error", error: "invalid_target" };
	return { kind: "ok" };
}
