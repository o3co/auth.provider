import type { Client } from "@mod/clients";
import type { BodyKind, HttpRequest } from "@mod/http";
import { contract, extensionPoint } from "@mod/kernel";
import type { Binding } from "@mod/sender-binding";
import type {
	AccessGrant,
	IssuanceRefused,
	IssuanceRequest,
	IssuedAccess,
	IssueLimits,
} from "@mod/tokens";

export type OAuthError =
	| "invalid_request"
	| "invalid_client"
	| "invalid_grant"
	| "unauthorized_client"
	| "unsupported_grant_type"
	| "invalid_scope"
	| "invalid_target";

/** An issuance a policy refused: a grant returns it unread, and the endpoint answers it. */
export interface Refused {
	readonly kind: "refused";
	readonly refusal: IssuanceRefused;
}

export type GrantOutcome =
	| { readonly kind: "issued"; readonly body: Readonly<Record<string, unknown>> }
	| {
			readonly kind: "error";
			/** An OAuth error code, or one the grant owns (such as a polled grant's). */
			readonly error: OAuthError | (string & {});
			readonly description?: string;
			/** `401` when the grant names it; otherwise `400`, or `401` for `invalid_client`. Another is ignored. */
			readonly status?: 400 | 401;
			/** More members of the error body, passed through unread but for the names an error answer drops. */
			readonly members?: Readonly<Record<string, unknown>>;
	  };

/** For an issuance's audience: the request's parameters, the audience when none is asked, and whether the issuance may have another (its owner decides). */
export interface TargetRequest {
	readonly param: (name: string) => string | undefined;
	readonly audience: readonly string[];
	readonly within: (audience: string) => boolean;
}
export type TargetVerdict =
	| { readonly kind: "audience"; readonly audience: readonly string[] }
	| { readonly kind: "error"; readonly error: "invalid_target"; readonly description: string };
/** A rule for the audience a request asks for, as resource indicators (RFC 8707) contribute. */
export interface TargetRule {
	target(request: TargetRequest): TargetVerdict;
	/** For a grant that takes no audience, or another endpoint that asks: a refusal when the request asks one anyway. */
	untargeted?(
		request: Pick<TargetRequest, "param">,
	): Extract<TargetVerdict, { readonly kind: "error" }> | undefined;
	/** For a parameter sent more than once: a refusal when it is one the rule reads. */
	repeated?(name: string): Extract<TargetVerdict, { readonly kind: "error" }> | undefined;
}
/** At most one; two refuse boot. */
export const targetRules = extensionPoint<TargetRule>("grants.target-rules", {
	multiplicity: "many",
});
/** The composed rule, provided by the token endpoint; with none, the default audience, the request unread. */
export const targets = contract<TargetRule>("grants.targets");

export interface GrantInput {
	readonly request: HttpRequest;
	readonly client: Client;
	/** A parameter's single string value; repeated parameters never reach a grant. */
	param(name: string): string | undefined;
	/** A parameter as sent: a JSON member of any type, or a form's single value. */
	value(name: string): unknown;
	/** The audience to issue: the default, or what the request asks within the ceiling; its error is the answer. */
	target(audience: readonly string[], within: (audience: string) => boolean): TargetVerdict;
	/** The binding every token issued for this request carries. */
	readonly binding?: Binding;
	/** Whether `issue` would allow the grant now; asked before anything is used up. */
	admits(
		grant: AccessGrant,
		from?: Pick<IssuanceRequest, "session" | "continuing">,
	): Promise<{ readonly kind: "allowed" } | Refused>;
	/** Issues with the request's grant type and binding once the policies allow it again; `session` and `continuing` go to them, the rest to the token. */
	issue(
		grant: AccessGrant,
		from?: Pick<IssueLimits, "notAfter" | "lifetimeSeconds"> &
			Pick<IssuanceRequest, "session" | "continuing">,
	): Promise<{ readonly kind: "issued"; readonly access: IssuedAccess } | Refused>;
}

export interface Grant {
	readonly grantType: string;
	/** The bodies the grant takes; a form only when left out. */
	readonly bodies?: readonly Exclude<BodyKind, "none">[];
	/** Whether it takes its audience from the request, through `target` or reading the parameters itself. */
	readonly targets?: true;
	/**
	 * What it reads that a browser sends by itself: `cookie` for a grant reading the session's cookie,
	 * which then checks the request's origin itself; `none` otherwise. A declaration, never a proof.
	 */
	readonly readsAmbient?: "none" | "cookie";
	handle(input: GrantInput): Promise<GrantOutcome | Refused>;
}

export const grants = extensionPoint<Grant>("grants", {
	multiplicity: "keyed",
	keyOf: (grant) => grant.grantType,
});

/** The grant types composed at boot, as the token endpoint dispatches to them. */
export const composedGrants = contract<ReadonlySet<string>>("grants.composed");

/** Told of each access token `issue` makes from a session, before the grant answers it. */
export interface SessionIssuance {
	/** A failure revokes the token, and `issue` throws it on. */
	issued(session: string, access: Pick<IssuedAccess, "id" | "expiresAt">): Promise<void>;
}

export const sessionIssuances = extensionPoint<SessionIssuance>("grants.session-issuances", {
	multiplicity: "many",
});
