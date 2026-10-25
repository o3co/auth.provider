import { createHash, randomBytes } from "node:crypto";

/** One challenge or verifier the shim added, for the run's record. */
export interface Added {
	readonly at: string;
	readonly added: "code_challenge" | "code_verifier";
	readonly value: string;
	readonly client: string | undefined;
	readonly state: string | undefined;
	readonly code?: string;
}

/** A request the shim gave a challenge to, waiting for its code. */
interface Pending {
	readonly client: string | undefined;
	readonly redirectUri: string | undefined;
	readonly state: string | undefined;
	readonly verifier: string;
}

/** The PKCE a request carries of its own: then the shim leaves it as it is. */
const ownPkce = (fields: URLSearchParams) =>
	fields.has("code_challenge") || fields.has("code_challenge_method");

/** Where a redirect goes, without its query: what a request's `redirect_uri` names. */
const target = (url: URL) => `${url.origin}${url.pathname}`;

/**
 * Gives PKCE to the requests that carry none, as a client would: an S256 challenge to an
 * authorization request, and its verifier to the token requests for the code that request got.
 * A request with PKCE of its own, right or wrong, and anything it did not see, pass as they are.
 */
export function pkceShim(
	given: { readonly verifier?: () => string; readonly now?: () => Date } = {},
) {
	const verifierOf = given.verifier ?? (() => randomBytes(32).toString("base64url"));
	const now = given.now ?? (() => new Date());
	const pending: Pending[] = [];
	const codes = new Map<string, Pending>();
	const added: Added[] = [];
	const note = (entry: Omit<Added, "at">) => added.push({ at: now().toISOString(), ...entry });
	return {
		/** The authorization request's fields as sent on, from its query or its form. */
		authorization(fields: URLSearchParams): URLSearchParams {
			if (ownPkce(fields)) return fields;
			const waiting: Pending = {
				client: fields.get("client_id") ?? undefined,
				redirectUri: fields.get("redirect_uri") ?? undefined,
				state: fields.get("state") ?? undefined,
				verifier: verifierOf(),
			};
			pending.push(waiting);
			const challenge = createHash("sha256").update(waiting.verifier).digest("base64url");
			note({
				added: "code_challenge",
				value: challenge,
				client: waiting.client,
				state: waiting.state,
			});
			const sent = new URLSearchParams(fields);
			sent.set("code_challenge", challenge);
			sent.set("code_challenge_method", "S256");
			return sent;
		},
		/** A `Location` the provider answered: a code there is tied to the latest request it answers. */
		redirected(location: string): void {
			const url = new URL(location);
			const code = url.searchParams.get("code");
			if (code === null) return;
			const state = url.searchParams.get("state") ?? undefined;
			const answered = pending.findLast(
				(p) => p.state === state && (p.redirectUri === undefined || p.redirectUri === target(url)),
			);
			if (answered !== undefined) codes.set(code, answered);
		},
		/** The token request's form as sent on. */
		token(form: URLSearchParams): URLSearchParams {
			if (form.get("grant_type") !== "authorization_code" || form.has("code_verifier")) return form;
			const code = form.get("code");
			const answered = code === null ? undefined : codes.get(code);
			if (code === null || answered === undefined) return form;
			note({
				added: "code_verifier",
				value: answered.verifier,
				client: answered.client,
				state: answered.state,
				code,
			});
			const sent = new URLSearchParams(form);
			sent.set("code_verifier", answered.verifier);
			return sent;
		},
		/** Each challenge and verifier added, in order. */
		records: (): readonly Added[] => [...added],
	};
}

export type PkceShim = ReturnType<typeof pkceShim>;
