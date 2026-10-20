import { contract } from "@mod/kernel";
import type { ConfiguredUrl } from "@mod/url-setting";

/** Why a destination was refused before anything was sent, or why its answer was. */
export type RefusalReason =
	| "scheme"
	| "userinfo"
	| "port"
	| "denied"
	| "not-allowed"
	| "special-address"
	/** A 3xx answer, which the sender refuses as this rule says: a redirect is never followed. */
	| "redirect"
	/** A credential where none may go: material fetched for its signature. */
	| "credential";

export class DestinationRefused extends Error {
	readonly reason: RefusalReason;
	constructor(reason: RefusalReason) {
		super(`outbound destination refused: ${reason}`);
		this.name = "DestinationRefused";
		this.reason = reason;
	}
}

/** What a caller narrows for its own calls; it never widens the operator's policy. */
export interface Narrower {
	/** Hosts as an operator lists them: `.name` is the name and every name under it. */
	readonly hosts?: readonly string[];
	readonly maxBytes?: number;
	readonly timeoutMs?: number;
	/**
	 * The operator's URL, as url-setting read it from their configuration: a request at its origin
	 * may reach a private address when `internal-hosts` lists the host. `true` says the same of the
	 * URL being sent, without naming it.
	 */
	readonly internal?: true | ConfiguredUrl;
}

/** The destination policy's refusals, as an operator reads them at boot, apart from sending: no name is resolved. */
export interface OutboundRefusals {
	/**
	 * Why the policy refuses the URL and what to set, `<reason>: <what to set>`, naming keys alone and
	 * never the URL's host, port or any other value; undefined when the policy lets it through.
	 */
	explained(url: string, narrower?: Narrower): string | undefined;
}

export const outboundRefusals = contract<OutboundRefusals>("outbound.refusals");

/**
 * A boot refusal of a URL the destination policy refuses, as every module says it:
 * `outbound's destination policy refuses <what>: <reason>: <what to set>`, `what` being `it` unless
 * given; undefined when the policy lets the URL through. The words are outbound's, never a caller's.
 */
export function destinationRefusal(
	refusals: OutboundRefusals,
	url: string,
	narrower?: Narrower,
	what = "it",
): string | undefined {
	const explained = refusals.explained(url, narrower);
	return explained && `outbound's destination policy refuses ${what}: ${explained}`;
}

/** Why a credential must not go to a set of URLs: more than one origin, or a URL neither https nor a named plain-loopback pair. */
export type CredentialRefusal = "origins" | "scheme";

/** Where a caller's credential may go, answered at boot, apart from sending. */
export interface CredentialPolicy {
	/** Why a credential must not be sent to these URLs, or undefined when it may go to every one. */
	refusalOf(urls: readonly string[]): CredentialRefusal | undefined;
}

export const credentialPolicy = contract<CredentialPolicy>("outbound.credentials");

/** Where a request is cut: its time and its body's bytes. */
export interface Limits {
	readonly maxBytes: number;
	readonly timeoutMs: number;
}

/** Where a caller's request is cut, answered at boot, apart from sending: the limits the sender cuts it at. */
export interface OutboundLimits {
	/** The operator's caps narrowed, never widened; throws RangeError on a narrowing that is not positive and finite. */
	of(narrower?: Narrower): Limits;
}

export const outboundLimits = contract<OutboundLimits>("outbound.limits");

/** A URL the policy lets through, as the sender reaches it. */
export interface Admitted {
	readonly url: URL;
	readonly host: string;
	readonly port: number;
	readonly plain: boolean;
	/** Reached at loopback addresses alone, as a named plain pair. */
	readonly loopback: boolean;
	/** The caller's URL is the operator's and `internal` lists its host: private addresses are reached. */
	readonly internal: boolean;
}

/** The operator's destination policy and caps, made once from the settings, for the sender and for boot alike. */
export interface Policy {
	/** Checks a URL before any name is resolved; `signed` material takes plain http at the caller's hosts. Throws DestinationRefused. */
	admit(url: string, narrower?: Narrower, signed?: boolean): Admitted;
	/** The addresses checked, all of them, for the sender to connect to the first; throws DestinationRefused on any it refuses or on none. */
	admitAddresses(addresses: readonly string[], admitted: Admitted): readonly string[];
	/** `<reason>: <what to set>` for a URL the policy refuses, resolving no name; undefined when it lets it through. */
	explain(url: string, narrower?: Narrower): string | undefined;
	credentialRefusal(urls: readonly string[]): CredentialRefusal | undefined;
	/** Whether a host is among an operator's list entries. */
	listed(host: string, entries: readonly string[]): boolean;
	/** Where a request under the narrowing is cut: the caps narrowed, never widened; throws RangeError on a narrowing that is not positive and finite. */
	limitsOf(narrower?: Narrower, signed?: boolean): Limits;
}

export { type HostEntry, hostEntryOf, policyOf, withinHosts } from "./policy.ts";
export { hostList, type PolicySettings, policySettings } from "./settings.ts";
