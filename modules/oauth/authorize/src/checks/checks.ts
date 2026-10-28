import { clientAllowance } from "@mod/client-allowance";
import type { Client } from "@mod/clients";
import { challengeShape, codeGrantType } from "@mod/code-grant";
import { targets } from "@mod/grants";
import type { BuildContext } from "@mod/kernel";
import { type Decision, recorded, refusal } from "../decision.ts";

const prompts = new Set(["none", "login", "consent", "select_account"]);

/** What a request asks, once its form is checked. */
export interface Checked {
	readonly kind: "checked";
	readonly challenge: string;
	readonly nonce?: string;
	readonly prompt: ReadonlySet<string>;
	/** `max_age` in ms, when asked. */
	readonly maxAgeMs?: number;
}

/** The request's form, in the order its refusals are given. */
export function checkRequest(
	client: Client,
	one: (name: string) => string | undefined,
	params: ReadonlyMap<string, string>,
): Checked | Decision {
	const responseType = one("response_type");
	if (!responseType) return refusal("invalid_request", "response_type is required");
	if (responseType !== "code") return refusal("unsupported_response_type");
	// OpenID Connect Core §6.1 and §6.2: no request object is taken, by value or by URI, each
	// told by its own code.
	if (params.has("request")) return refusal("request_not_supported");
	if (params.has("request_uri")) return refusal("request_uri_not_supported");
	const mode = one("response_mode");
	if (mode !== undefined && mode !== "query")
		return refusal("invalid_request", "response_mode must be query");
	if (!clientAllowance.allowsGrant(client, codeGrantType)) {
		const description = `client is not authorized for grant_type '${codeGrantType}'`;
		return recorded("unauthorized_client", "grant_type_not_allowed", description);
	}
	const challenge = one("code_challenge");
	if (!challenge) return refusal("invalid_request", "PKCE with S256 is required");
	// RFC 7636 §4.3: a method left out is plain, which is not taken either.
	if (one("code_challenge_method") !== "S256")
		return refusal("invalid_request", "code_challenge_method is not supported: only S256");
	if (!challengeShape.test(challenge))
		return refusal("invalid_request", "code_challenge is malformed");
	const nonce = one("nonce");
	if (nonce !== undefined && nonce.length > 256)
		return refusal("invalid_request", "nonce too long");
	const prompt = new Set((one("prompt") ?? "").split(" ").filter((p) => p !== ""));
	if ([...prompt].some((p) => !prompts.has(p)) || (prompt.has("none") && prompt.size > 1)) {
		return refusal("invalid_request", "bad prompt");
	}
	const maxAgeText = one("max_age");
	if (maxAgeText !== undefined && !/^\d{1,9}$/.test(maxAgeText))
		return refusal("invalid_request", "bad max_age");
	return {
		kind: "checked",
		challenge,
		...(nonce !== undefined ? { nonce } : {}),
		prompt,
		...(maxAgeText !== undefined ? { maxAgeMs: Number(maxAgeText) * 1000 } : {}),
	};
}

/**
 * The scope and audience the client may be issued for the requested scope. With `openid`
 * required, the request itself must name it; a client's default does not count.
 */
export function checkScope(
	client: Client,
	scope: string | undefined,
	issuer: string,
	openidRequired: boolean,
) {
	const allowed = clientAllowance.allowedIssuance(client, scope, issuer);
	if (allowed.kind === "allowed") {
		const named = clientAllowance.parseScope(scope) ?? [];
		return openidRequired && !named.includes("openid")
			? refusal("invalid_scope", "openid scope is required")
			: allowed;
	}
	// Left out with no default to take, the scope is decided for the client, and recorded.
	return clientAllowance.parseScope(scope)?.length === 0
		? recorded(allowed.error, "scope_omitted_without_default", allowed.description)
		: refusal(allowed.error, allowed.description);
}

/** The audience a request asks for, within what the client may be issued, or the refusal to give. */
export type TargetCheck = (
	client: Client,
	one: (name: string) => string | undefined,
	audience: readonly string[],
	issuer: string,
) => { readonly kind: "audience"; readonly audience: readonly string[] } | Refused;

/** A refusal, the only decision the target check gives besides the audience. */
type Refused = Extract<Decision, { kind: "refuse" }>;

/** What `targetCheckOver` takes. */
export const targetCheckTakes = [targets];

/** The target check over `token-endpoint`'s composed rule for the audience a request asks for. */
export async function targetCheckOver(c: Pick<BuildContext<unknown>, "get">): Promise<TargetCheck> {
	const rule = await c.get(targets);
	return (client, one, audience, issuer) => {
		const within = (resource: string) => clientAllowance.allowsAudience(client, resource, issuer);
		const verdict = rule.target({ param: one, audience, within });
		if (verdict.kind === "audience") return verdict;
		return { kind: "refuse", error: verdict.error, description: verdict.description };
	};
}
