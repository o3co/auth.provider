/** What a step decides for a request whose redirect URI is trusted; only `route` turns it into an answer. */
export type Decision =
	| {
			readonly kind: "refuse";
			readonly error: string;
			readonly description?: string;
			/** Why it was refused, on the refusals decided for the client or its consent, which are recorded. */
			readonly reason?: string;
			/** The issuance policy that refused, recorded with its reason. */
			readonly policy?: string;
	  }
	/** Refused at the endpoint, never sent back: a refusal whose login the request is too long to reach. */
	| { readonly kind: "answer"; readonly error: string; readonly description?: string }
	/** The browser goes to another page first: to log in, to raise its authentication, or to consent. */
	| { readonly kind: "send"; readonly to: string }
	| { readonly kind: "code"; readonly code: string; readonly subject: string };

export const refusal = (error: string, description?: string): Decision => ({
	kind: "refuse",
	error,
	...(description ? { description } : {}),
});

/** A refusal decided for the client or its consent, recorded with its reason. */
export const recorded = (error: string, reason: string, description?: string): Decision => ({
	kind: "refuse",
	error,
	...(description ? { description } : {}),
	reason,
});

/**
 * This endpoint's URL for the request again, without the named parameters (`prompt:<word>` drops
 * one prompt word), and with the given ones added at the end.
 */
export type Again = (
	without: readonly string[],
	add?: readonly (readonly [string, string])[],
) => string;
