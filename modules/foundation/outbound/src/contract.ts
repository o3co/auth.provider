import { contract, deepFreeze, Unavailable } from "@mod/kernel";

/** Why a destination was refused before anything was sent, or why its answer was. */
export type RefusalReason =
	| "scheme"
	| "userinfo"
	| "port"
	| "denied"
	| "not-allowed"
	| "special-address"
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

/** Why no usable answer came, for a caller to log by; it carries no value and no body. */
export type OutboundFailure =
	| "timeout"
	| "too-large"
	| "unreachable"
	| "unsupported-answer"
	| "busy"
	/** The proxy would not open the tunnel. */
	| "proxy-refused";

export class OutboundUnavailable extends Unavailable {
	readonly failure: OutboundFailure;
	constructor(failure: OutboundFailure) {
		super("outbound");
		this.failure = failure;
	}
}

export interface OutboundRequest {
	readonly method?: "GET" | "POST";
	readonly headers?: Readonly<Record<string, string>>;
	readonly body?: string | Uint8Array;
	/** The Authorization value, sent as that header; a secret never told. Not beside an Authorization header. */
	readonly credential?: string;
}

/** What a caller narrows for its own calls; it never widens the operator's policy. */
export interface Narrower {
	/** Hosts as an operator lists them: `.name` is the name and every name under it. */
	readonly hosts?: readonly string[];
	readonly maxBytes?: number;
	readonly timeoutMs?: number;
	/**
	 * The URL is the operator's, from their configuration, never one given from outside; its host may
	 * then reach a private address when `internal-hosts` lists it.
	 */
	readonly internal?: true;
}

export interface OutboundResponse {
	readonly status: number;
	/** By lowercased name; repeated headers are joined with ", ". */
	readonly headers: ReadonlyMap<string, string>;
	readonly body: Uint8Array;
}

export interface Outbound {
	/**
	 * Sends one request under the destination policy. Throws DestinationRefused for a destination or
	 * a redirect the policy refuses, and OutboundUnavailable when no usable answer comes in time and size.
	 */
	fetch(url: string, request?: OutboundRequest, narrower?: Narrower): Promise<OutboundResponse>;
}

export const outbound = contract<Outbound>("outbound");

/** The destination policy answered at boot, apart from sending: no name is resolved. */
export interface OutboundPolicy {
	/** Why the policy refuses the URL, or undefined when it lets it through. */
	refusalOf(url: string, narrower?: Narrower): RefusalReason | undefined;
}

export const outboundPolicy = contract<OutboundPolicy>("outbound.policy");

/** Why a credential must not go to a set of URLs: more than one origin, or a URL neither https nor a named plain-loopback pair. */
export type CredentialRefusal = "origins" | "scheme";

/** Where a caller's credential may go, answered at boot, apart from sending. */
export interface CredentialPolicy {
	/** Why a credential must not be sent to these URLs, or undefined when it may go to every one. */
	refusalOf(urls: readonly string[]): CredentialRefusal | undefined;
}

export const credentialPolicy = contract<CredentialPolicy>("outbound.credentials");

/** An answer read as JSON: one object from the status asked for (`200` unless named), frozen, or any other answer with its status. */
export type JsonAnswer =
	| { readonly kind: "object"; readonly value: Readonly<Record<string, unknown>> }
	| { readonly kind: "other"; readonly status: number };

export function jsonObjectOf(answer: OutboundResponse, status = 200): JsonAnswer {
	const other = { kind: "other", status: answer.status } as const;
	if (answer.status !== status) return other;
	try {
		const value: unknown = JSON.parse(
			new TextDecoder("utf-8", { fatal: true }).decode(answer.body),
		);
		const isObject = typeof value === "object" && value !== null && !Array.isArray(value);
		return isObject
			? { kind: "object", value: deepFreeze(value as Record<string, unknown>) }
			: other;
	} catch {
		return other;
	}
}

export { type HostEntry, hostEntryOf, withinHosts } from "./policy.ts";

/** What a caller of signed material narrows: the hosts it fetches from are always named. */
export interface SignedNarrower extends Narrower {
	readonly hosts: readonly string[];
}

/**
 * Fetches material whose signature the caller checks before using any of it. As `outbound`, but
 * plain http is taken too, at public addresses, and only from the hosts the caller names; naming
 * none refuses every destination.
 */
export interface SignedOutbound {
	fetch(
		url: string,
		request: Omit<OutboundRequest, "credential">,
		narrower: SignedNarrower,
	): Promise<OutboundResponse>;
}

export const signedOutbound = contract<SignedOutbound>("outbound.signed");
