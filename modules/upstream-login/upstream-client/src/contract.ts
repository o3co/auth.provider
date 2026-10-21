import { isUnavailable, Unavailable } from "@mod/kernel";
import { type JsonAnswer, jsonObjectOf, type OutboundResponse } from "@mod/outbound";
import {
	type AuthorizationStart,
	type UpstreamRefresh,
	UpstreamRefused,
	type UpstreamTokens,
} from "@mod/upstreams";
import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

export { type IdTokenLogin, type IdTokenRules, idTokenReaderOf } from "./id-token/reader.ts";

/** An endpoint an IdP's settings name. */
export const endpointSetting = urlSetting({ schemes: ["https", "http"] });

/** One scope an IdP's settings ask for (RFC 6749 §3.3). */
export const scopeSetting = z.string().regex(/^[\x21\x23-\x5b\x5d-\x7e]+$/);

/** A credential an IdP's settings name, sent form-urlencoded, which half a surrogate pair cannot be. */
export const credentialSetting = z
	.string()
	.refine((value) => value.trim() !== "", "not blank")
	.refine((value) => value.isWellFormed(), "well-formed text");

/** The client's ID and secret an IdP's settings name; a type adds its own settings by `extend`. */
export const clientSetting = z.strictObject({
	"client-id": credentialSetting.describe(
		"The client ID this provider is registered under at the IdP.",
	),
	"client-secret": credentialSetting.describe(
		"The client secret the IdP gave this provider, sent to its token endpoint.",
	),
});

/** Runs a type's call; throws only UpstreamRefused or Unavailable, so no library text reaches federation. */
export async function guarded<T>(run: () => Promise<T>): Promise<T> {
	try {
		return await run();
	} catch (error) {
		if (isUnavailable(error) || UpstreamRefused.is(error)) throw error;
		// Anything else, such as a destination outbound refuses, is the upstream refusing.
		throw new UpstreamRefused();
	}
}

/** A start's authorization URL: federation's request, then a type's own parameters of other names. */
export function authorizationUrl(
	endpoint: string,
	start: AuthorizationStart,
	client: { readonly clientId: string; readonly scopes: readonly string[] },
	own: Readonly<Record<string, string>> = {},
): string {
	const url = new URL(endpoint);
	const request = {
		response_type: "code",
		client_id: client.clientId,
		redirect_uri: start.redirectUri,
		scope: client.scopes.join(" "),
		state: start.state,
		code_challenge: start.challenge,
		code_challenge_method: start.challengeMethod,
	};
	const added = Object.entries(own).filter(([name]) => !Object.hasOwn(request, name));
	for (const [name, value] of [...Object.entries(request), ...added])
		url.searchParams.set(name, value);
	return url.href;
}

/** What `schema` reads in an upstream's answer; anything else is the upstream refusing. */
export function answerOf<T>(read: JsonAnswer, schema: z.ZodType<T>): T {
	// No JSON object of a 200 is the upstream refusing, whatever the schema takes.
	if (read.kind !== "object") throw new UpstreamRefused();
	const parsed = schema.safeParse(read.value);
	if (!parsed.success) throw new UpstreamRefused();
	return parsed.data;
}

const tokenAnswer = z.looseObject({
	access_token: z.string().min(1),
	token_type: z.string().min(1),
	refresh_token: z.string().min(1).optional(),
	expires_in: z.number().int().nonnegative().optional(),
	scope: z.string().optional(),
	id_token: z.string().min(1).optional(),
});

/**
 * A token endpoint's answer: its tokens, and apart its id_token, which the type checks before it
 * hands it on. A scope left out is the one `asked` (RFC 6749 §5.1); with `asked` left out, it refuses.
 */
export function tokenAnswerOf(
	read: JsonAnswer,
	asked?: readonly string[],
): { readonly tokens: UpstreamTokens; readonly idToken?: string } {
	const answer = answerOf(read, tokenAnswer);
	const scope = answer.scope?.split(" ").filter(Boolean) ?? asked;
	if (scope === undefined) throw new UpstreamRefused();
	return {
		tokens: {
			accessToken: answer.access_token,
			tokenType: answer.token_type,
			...(answer.refresh_token === undefined ? {} : { refreshToken: answer.refresh_token }),
			...(answer.expires_in === undefined ? {} : { expiresInSeconds: answer.expires_in }),
			scope,
		},
		...(answer.id_token === undefined ? {} : { idToken: answer.id_token }),
	};
}

/** The `error` a 400 answer names (RFC 6749 §5.2); any other answer names none. */
function errorOf(answer: OutboundResponse): unknown {
	const body = jsonObjectOf(answer, 400);
	return body.kind === "object" ? body.value.error : undefined;
}

/** The errors by which an upstream asks the user to act there first (OpenID Connect Core §3.1.2.6). */
const asksTheUser = new Set([
	"interaction_required",
	"login_required",
	"consent_required",
	"account_selection_required",
]);

/** `retry-after` as delta-seconds only (RFC 9110 §10.2.3); an empty or other value is none. */
function retryAfterOf(value: string | undefined): number | undefined {
	if (value === undefined || !/^[0-9]+$/.test(value)) return undefined;
	const seconds = Number(value);
	return Number.isSafeInteger(seconds) ? seconds : undefined;
}

/**
 * A token endpoint's answer to a refresh; `what` names the upstream that is unavailable. An
 * id_token in it is not checked, so it is not handed on.
 */
export function refreshAnswerOf(
	answer: OutboundResponse,
	asked: readonly string[],
	what: string,
): UpstreamRefresh {
	if (answer.status === 429) {
		const seconds = retryAfterOf(answer.headers.get("retry-after"));
		return { kind: "limited", ...(seconds === undefined ? {} : { retryAfterSeconds: seconds }) };
	}
	if (answer.status >= 500) throw new Unavailable(what);
	const error = errorOf(answer);
	if (error === "invalid_grant") return { kind: "invalid_grant" };
	if (typeof error === "string" && asksTheUser.has(error)) return { kind: "interaction_required" };
	return { kind: "refreshed", tokens: tokenAnswerOf(jsonObjectOf(answer), asked).tokens };
}

/** A value form-urlencoded, as URLSearchParams writes it: a space is `+`. */
const formEncoded = (value: string) => new URLSearchParams({ "": value }).toString().slice(1);

/** The HTTP Basic client authentication, each part form-urlencoded first (RFC 6749 §2.3.1). */
export function basicAuthorization(clientId: string, secret: string): string {
	const pair = `${formEncoded(clientId)}:${formEncoded(secret)}`;
	return `Basic ${Buffer.from(pair).toString("base64")}`;
}

/**
 * An end-session URL (RP-Initiated Logout): the parameters it fixes, each where given, then a type's
 * own parameters of other names, so a type never replaces or places a fixed one.
 */
export function endSessionUrl(
	endpoint: string,
	at: {
		readonly idTokenHint?: string;
		readonly postLogoutRedirectUri?: string;
		readonly state?: string;
		readonly clientId?: string;
	},
	own: Readonly<Record<string, string>> = {},
): string {
	const url = new URL(endpoint);
	const fixed = {
		id_token_hint: at.idTokenHint,
		post_logout_redirect_uri: at.postLogoutRedirectUri,
		state: at.state,
		client_id: at.clientId,
	};
	const added = Object.entries(own).filter(([name]) => !Object.hasOwn(fixed, name));
	for (const [name, value] of [...Object.entries(fixed), ...added]) {
		if (value) url.searchParams.set(name, value);
	}
	return url.href;
}
