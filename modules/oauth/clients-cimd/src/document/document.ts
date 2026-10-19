import { isIP } from "node:net";
import { type AllowanceLists, clientAllowance } from "@mod/client-allowance";
import type { ClientRecord } from "@mod/clients";
import { codeGrantType } from "@mod/code-grant";
import { clientSection, displayed } from "@mod/consent";
import { redirects } from "@mod/redirect-uris";
import { refreshGrantType } from "@mod/refresh";

/** The grants a document client may hold: the code, and refresh when its document names it. */
const documentGrants = [codeGrantType, refreshGrantType];

/**
 * The id as a document URL: https, a path other than `/`, no query, fragment, user information,
 * IP literal or localhost, written exactly as the URL parser writes it (so no trailing dot, default
 * port, upper case or other encoding).
 */
export function documentUrl(id: string): URL | undefined {
	const url = URL.parse(id);
	if (!url || url.href !== id || url.protocol !== "https:") return undefined;
	if (url.pathname === "/" || id.includes("?") || id.includes("#")) return undefined;
	if (url.username !== "" || url.password !== "") return undefined;
	const host = url.hostname;
	if (host.startsWith("[") || isIP(host) !== 0 || host.endsWith(".")) return undefined;
	return host === "localhost" || host.endsWith(".localhost") ? undefined : url;
}

/** A document refused, and why, in words of this module alone. */
export interface Refused {
	readonly refused: string;
}

/** An https URL kept as written, so nothing the parser would drop (whitespace, control characters). */
const isHttps = (text: string) =>
	!/[\s\p{Cc}]/u.test(text) && URL.parse(text)?.protocol === "https:";

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

/** The fields this module reads itself, as checked; the owners' schemas check the rest. */
interface Checked {
	readonly redirectUris: readonly string[];
	readonly name: string;
	readonly uri: string | undefined;
}

/** The fields this module reads itself, once checked, or why the document is refused. */
function checkedOf(url: URL, doc: Readonly<Record<string, unknown>>): Checked | Refused {
	if (doc.client_id !== url.href) return { refused: "client_id" };
	if ("client_secret" in doc || "client_secret_expires_at" in doc) {
		return { refused: "client_secret" };
	}
	const method = doc.token_endpoint_auth_method;
	if (method !== undefined && method !== "none") return { refused: "token_endpoint_auth_method" };
	const redirectUris = doc.redirect_uris;
	if (!strings(redirectUris) || redirectUris.length === 0) return { refused: "redirect_uris" };
	const types = doc.response_types;
	if (types !== undefined && !(strings(types) && types.includes("code"))) {
		return { refused: "response_types" };
	}
	const name = doc.client_name;
	if (typeof name !== "string" || name.trim() === "") return { refused: "client_name" };
	const uri = doc.client_uri;
	if (uri !== undefined && !(typeof uri === "string" && isHttps(uri))) {
		return { refused: "client_uri" };
	}
	return { redirectUris, name, uri };
}

/**
 * The public client a document describes, its sections put as each owner takes them, or why it is
 * refused. The ceiling's grants are the code and refresh; its scopes and audiences the operator's.
 */
export function recordOf(
	url: URL,
	doc: Readonly<Record<string, unknown>>,
	ceiling: Omit<AllowanceLists, "grants">,
): ClientRecord | Refused {
	const checked = checkedOf(url, doc);
	if ("refused" in checked) return checked;
	const asked = askedOf(doc);
	if ("refused" in asked) return asked;
	const allowances = clientAllowance.allowancesWithin(
		{ ...ceiling, grants: documentGrants },
		asked,
	);
	// A document never asks audiences, so this guards only the contract's undefined.
	if (allowances === undefined) return { refused: "audiences" };
	return {
		id: url.href,
		kind: "public",
		method: "none",
		sections: {
			[redirects.name]: { "redirect-uris": checked.redirectUris },
			...allowances,
			[clientSection.name]: displayed({ name: checked.name, uri: checked.uri, host: url.hostname }),
		},
	};
}
