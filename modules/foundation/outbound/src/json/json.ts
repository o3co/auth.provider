import { deepFreeze } from "@mod/kernel";
import { DestinationRefused, type Narrower, type RefusalReason } from "@mod/outbound-policy";
import {
	isOutboundUnavailable,
	type Outbound,
	type OutboundFailure,
	type OutboundResponse,
} from "../contract.ts";

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

/** Why a send failed, in outbound's words: a refused destination's reason, a failure, or `no-answer` for anything else. */
export function sendFailureOf(error: unknown): RefusalReason | OutboundFailure | "no-answer" {
	if (DestinationRefused.is(error)) return error.reason;
	if (isOutboundUnavailable(error)) return error.failure;
	return "no-answer";
}

/** A JSON call's request: its body, and the credential, as a Bearer token or, with a header named, as given there. */
export interface JsonPost {
	readonly url: string;
	readonly body: unknown;
	readonly credential?: string | undefined;
	/** The header the credential goes as, in place of Authorization, its value as given (`credentialHeader`). */
	readonly credentialHeader?: string | undefined;
	readonly narrower?: Narrower | undefined;
}

const jsonHeaders = deepFreeze({ accept: "application/json", "content-type": "application/json" });

/**
 * POSTs `body` as JSON, asking JSON back, under the destination policy and `narrower`. A send that
 * fails throws what `failed` makes of its kind (`sendFailureOf`); any answer is the caller's to read.
 */
export function postJson(
	out: Outbound,
	{ url, body, credential, credentialHeader, narrower }: JsonPost,
	failed: (reason: ReturnType<typeof sendFailureOf>) => Error,
): Promise<OutboundResponse> {
	const sent =
		credential === undefined
			? {}
			: credentialHeader === undefined
				? { credential: `Bearer ${credential}` }
				: { credential, credentialHeader };
	const request = {
		method: "POST",
		headers: jsonHeaders,
		body: JSON.stringify(body),
		...sent,
	} as const;
	return out.fetch(url, request, narrower).catch((error: unknown) => {
		throw failed(sendFailureOf(error));
	});
}
