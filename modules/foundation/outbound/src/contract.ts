import { contract, deepFreeze, Unavailable } from "@mod/kernel";
import type { Narrower } from "@mod/outbound-policy";

// The destination policy's own, as `fetch` takes and throws them.
export { DestinationRefused, type Narrower, type RefusalReason } from "@mod/outbound-policy";
export { credentialHeaderRefusal } from "./credential/credential.ts";

/** Why no usable answer came, for a caller to log by; it carries no value and no body. */
export type OutboundFailure =
	| "timeout"
	| "too-large"
	| "unreachable"
	| "unsupported-answer"
	| "busy"
	/** The proxy would not open the tunnel. */
	| "proxy-refused";

/** One mark for every copy of outbound, so a second bundled copy's failure is still told apart. */
const outboundUnavailableMark = Symbol.for("@mod/outbound.unavailable");

export class OutboundUnavailable extends Unavailable {
	readonly failure: OutboundFailure;
	readonly [outboundUnavailableMark] = true;
	constructor(failure: OutboundFailure) {
		super("outbound");
		this.failure = failure;
	}
}

/** Whether an error is outbound's no usable answer, by its mark rather than its class. */
export function isOutboundUnavailable(error: unknown): error is OutboundUnavailable {
	return (
		typeof error === "object" &&
		error !== null &&
		(error as { readonly [outboundUnavailableMark]?: unknown })[outboundUnavailableMark] === true
	);
}

export interface OutboundRequest {
	readonly method?: "GET" | "POST";
	readonly headers?: Readonly<Record<string, string>>;
	readonly body?: string | Uint8Array;
	/** The Authorization value, sent as that header; a secret never told. The only way to send one: headers may not name it. */
	readonly credential?: string;
	/**
	 * The header the credential goes as, in place of Authorization, its value as given: one a ledger
	 * asks a token in. Under the credential's rules alike, and headers may not name it either, in any
	 * case; a name outbound or the request's shape decides (its own, the host, the framing,
	 * `content-type`, `cookie`, `proxy-authorization`), one that is no header token, or one without
	 * a credential is a TypeError.
	 */
	readonly credentialHeader?: string;
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
		request: Omit<OutboundRequest, "credential" | "credentialHeader">,
		narrower: SignedNarrower,
	): Promise<OutboundResponse>;
}

export const signedOutbound = contract<SignedOutbound>("outbound.signed");
