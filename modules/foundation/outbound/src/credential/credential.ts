import { DestinationRefused, type OutboundRequest } from "../contract.ts";

/** One header value: printable ASCII on one line, no space at either end. */
const headerValue = /^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$/;

/** A header's name as HTTP writes one (RFC 9110's token). */
const headerName = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
/** The header a credential goes as: Authorization, or the one the request names, lowercased. */
function credentialHeaderOf(
	named: string | undefined,
	credential: string | undefined,
	notForCredential: ReadonlySet<string>,
): string {
	if (named === undefined) return "authorization";
	if (credential === undefined) {
		throw new TypeError(
			"outbound: a credential header names where a credential goes, and none is given",
		);
	}
	const name = named.toLowerCase();
	if (!headerName.test(named) || notForCredential.has(name)) {
		throw new TypeError(
			"outbound: a credential goes as a header of its own, never one outbound or the request's shape decides",
		);
	}
	return name;
}

/**
 * The request as sent, `decided` the headers outbound sets alone: its credential as the
 * Authorization header, or the one it names; none for signed material. Its value is never told.
 */
export function requestSent(decided: ReadonlySet<string>) {
	// Names a credential may not go as: outbound's own and the framing, and what shapes the request.
	const notForCredential: ReadonlySet<string> = new Set([
		...decided,
		"content-type",
		"cookie",
		"proxy-authorization",
	]);
	return (request: OutboundRequest, signed: boolean): OutboundRequest =>
		sent(request, signed, notForCredential);
}

function sent(
	request: OutboundRequest,
	signed: boolean,
	notForCredential: ReadonlySet<string>,
): OutboundRequest {
	const { credential, credentialHeader, ...rest } = request;
	const header = credentialHeaderOf(credentialHeader, credential, notForCredential);
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
