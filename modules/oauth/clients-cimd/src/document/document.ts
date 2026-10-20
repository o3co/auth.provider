import { isIP } from "node:net";
import { type AllowanceLists, clientAllowance } from "@mod/client-allowance";
import type { ClientRecord, Section } from "@mod/clients";
import { codeGrantType } from "@mod/code-grant";
import { refreshGrantType } from "@mod/refresh";
import { isLoopbackName } from "@mod/url-setting";

/** The grants a document client may hold: the code, and refresh when its document names it. */
const documentGrants = [codeGrantType, refreshGrantType];

/**
 * The id as a document URL: https, a path other than `/`, no query, fragment, user information,
 * IP literal or loopback host (url-setting's `isLoopbackName`), written exactly as the URL parser writes it (so no trailing dot, default
 * port, upper case or other encoding).
 */
export function documentUrl(id: string): URL | undefined {
	const url = URL.parse(id);
	if (!url || url.href !== id || url.protocol !== "https:") return undefined;
	if (url.pathname === "/" || id.includes("?") || id.includes("#")) return undefined;
	if (url.username !== "" || url.password !== "") return undefined;
	const host = url.hostname;
	if (host.startsWith("[") || isIP(host) !== 0 || host.endsWith(".")) return undefined;
	return isLoopbackName(host) ? undefined : url;
}

/** A document refused, and why, in words of this module alone. */
export interface Refused {
	readonly refused: string;
}

/** The fields a document client cannot do without, in RFC 7591's words: a composed section must copy each. */
export const neededFields = ["redirect_uris", "client_name"] as const;

const strings = (value: unknown): value is readonly string[] =>
	Array.isArray(value) && value.every((item) => typeof item === "string");

/** What the document asks within the ceiling, or why it is refused. */
function askedOf(doc: Readonly<Record<string, unknown>>): Partial<AllowanceLists> | Refused {
	const grantTypes = doc.grant_types ?? [codeGrantType];
	if (!strings(grantTypes) || !grantTypes.includes(codeGrantType)) {
		return { refused: "grant_types" };
	}
	if (doc.scope === undefined) return { grants: grantTypes };
	const scopes = typeof doc.scope === "string" ? clientAllowance.parseScope(doc.scope) : undefined;
	return scopes === undefined ? { refused: "scope" } : { grants: grantTypes, scopes };
}

/** Why the document is refused by CIMD's own rules, or nothing; the owners' copies and schemas take the rest. */
function refusalOf(url: URL, doc: Readonly<Record<string, unknown>>): Refused | undefined {
	if (doc.client_id !== url.href) return { refused: "client_id" };
	if ("client_secret" in doc || "client_secret_expires_at" in doc) {
		return { refused: "client_secret" };
	}
	const method = doc.token_endpoint_auth_method;
	if (method !== undefined && method !== "none") return { refused: "token_endpoint_auth_method" };
	// The section takes an empty list; a document client, which has the code flow alone, needs one.
	const redirectUris = doc.redirect_uris;
	if (!strings(redirectUris) || redirectUris.length === 0) return { refused: "redirect_uris" };
	const types = doc.response_types;
	if (types !== undefined && !(strings(types) && types.includes("code"))) {
		return { refused: "response_types" };
	}
	return undefined;
}

/**
 * The public client a document describes, each section as its owner copies it, or why it is
 * refused. The ceiling's grants are the code and refresh; its scopes and audiences the operator's.
 */
export function recordOf(
	url: URL,
	doc: Readonly<Record<string, unknown>>,
	ceiling: Omit<AllowanceLists, "grants">,
	copies: readonly Section<unknown>[],
): ClientRecord | Refused {
	const refused = refusalOf(url, doc);
	if (refused) return refused;
	const asked = askedOf(doc);
	if ("refused" in asked) return asked;
	const allowances = clientAllowance.allowancesWithin(
		{ ...ceiling, grants: documentGrants },
		asked,
	);
	// A document never asks audiences, so this guards only the contract's undefined.
	if (allowances === undefined) return { refused: "audiences" };
	const copied: Record<string, unknown> = {};
	const from = { id: url.href, host: url.hostname };
	for (const section of copies) {
		const copy = section.fromDocument?.(doc, from);
		if (copy === undefined) continue;
		if ("refused" in copy) return { refused: copy.refused };
		copied[section.name] = copy.value;
	}
	return { id: url.href, kind: "public", method: "none", sections: { ...copied, ...allowances } };
}

/** The names of the sections this module computes itself, which no copy may give. */
export const computedSections = Object.keys(
	clientAllowance.allowancesWithin({ grants: [], scopes: [], audiences: [] }, {}) ?? {},
);
