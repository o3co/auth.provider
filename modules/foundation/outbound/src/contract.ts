import { contract, deepFreeze, Unavailable } from "@mod/kernel";
import type { Narrower } from "@mod/outbound-policy";

// The destination policy's own, offered here too while callers still import them from outbound.
export {
	type CredentialPolicy,
	type CredentialRefusal,
	credentialPolicy,
	DestinationRefused,
	destinationRefusal,
	type HostEntry,
	hostEntryOf,
	type Narrower,
	type OutboundRefusals,
	outboundRefusals,
	type RefusalReason,
	withinHosts,
} from "@mod/outbound-policy";

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
	/** The Authorization value, sent as that header; a secret never told. The only way to send one: headers may not name it. */
	readonly credential?: string;
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
		request: Omit<OutboundRequest, "credential">,
		narrower: SignedNarrower,
	): Promise<OutboundResponse>;
}

export const signedOutbound = contract<SignedOutbound>("outbound.signed");
