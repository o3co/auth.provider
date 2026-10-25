import { DestinationRefused } from "@mod/outbound-policy";
import type { OutboundRequest } from "../contract.ts";
import { decided } from "../transport.ts";

/** One header value: printable ASCII on one line, no space at either end. */
const headerValue = /^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$/;

/** A header's name as HTTP writes one (RFC 9110's token). */
const headerName = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/** Names a credential may not go as: outbound's own and the framing, and what shapes the request. */
const notForCredential: ReadonlySet<string> = new Set([
	...decided,
	"content-type",
	"cookie",
	"proxy-authorization",
]);

/**
 * Why a credential may not go as the header `name`, in any case; none where it may. What a request
 * naming it is refused with, for a caller to refuse its own setting at boot.
 */
export function credentialHeaderRefusal(name: string): string | undefined {
	if (!headerName.test(name))
		return "a credential goes as a header name, a token of its characters";
	if (notForCredential.has(name.toLowerCase())) {
		return "a credential goes as a header of its own, never one outbound or the request's shape decides";
	}
	return undefined;
}

/** The header a credential goes as: Authorization, or the one the request names, lowercased. */
function credentialHeaderOf(named: string | undefined, credential: string | undefined): string {
	if (named === undefined) return "authorization";
	if (credential === undefined) {
		throw new TypeError(
			"outbound: a credential header names where a credential goes, and none is given",
		);
	}
	const refused = credentialHeaderRefusal(named);
	if (refused !== undefined) throw new TypeError(`outbound: ${refused}`);
	return named.toLowerCase();
}

/**
 * The request as sent: its credential as the Authorization header, or the one it names; none for
 * signed material. Its value is never told.
 */
export function sentRequest(request: OutboundRequest, signed: boolean): OutboundRequest {
	const { credential, credentialHeader, ...rest } = request;
	const header = credentialHeaderOf(credentialHeader, credential);
	// A credential goes only as a credential, under its rules: never one a caller writes, in any case.
	const written = Object.keys(rest.headers ?? {}).map((name) => name.toLowerCase());
	if (written.includes("authorization") || written.includes(header)) {
		throw new TypeError("outbound: a credential's header goes as the request's credential");
	}
	if (credential === undefined) return rest;
	if (signed) throw new DestinationRefused("credential");
	if (!headerValue.test(credential)) {
		throw new TypeError("outbound: a credential is one header value, printable ASCII on one line");
	}
	return { ...rest, headers: { ...rest.headers, [header]: credential } };
}
