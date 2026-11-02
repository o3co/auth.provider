import type { Client } from "@mod/clients";
import type { Keys } from "@mod/keys";
import type { LogoutReturn } from "../../contract.ts";
import { returnsTo } from "../../registration/registration.ts";

/** The parameter a carried request goes in, to the logout's `GET` and to the confirmation's. */
export const carriedParam = "request";
/** The kind of the token a carried request is. */
const carriedType = "logout-request+jwt";

/**
 * A logout `ending` checked and carries on in the browser's URL: the session the hint names, its
 * client, and the return the client registered with its `state`. It closes nothing by itself.
 */
export interface CarriedRequest {
	readonly sid: string;
	readonly client?: string;
	readonly back: LogoutReturn;
}

/** What a token carries on: a return, its client, and the time (epoch seconds) it may be used until. */
export interface Carried {
	readonly client?: string;
	readonly back: LogoutReturn;
	readonly exp?: number;
}

export interface CarriedParts {
	readonly keys: Pick<Keys, "sign" | "verify">;
	/** The client records a carried return is held to, as they are when it is used. */
	readonly clients: { find(id: string): Promise<Client | undefined> };
	readonly issuer: string;
	/** The logout endpoint's URL, which a carried request names as its audience. */
	readonly logoutUrl: string;
	/** How long, in seconds, the browser has to follow a carried request (the package's `confirm-within`). */
	readonly withinSeconds: number;
	readonly now: () => number;
}

/** A return as a token's claims carry it: its client, the return and its `state`, each where there is one. */
export const carriedClaims = (request: Pick<Carried, "client" | "back">) => ({
	...(request.client === undefined ? {} : { client: request.client }),
	...(request.back.postLogoutRedirectUri === undefined
		? {}
		: { back: request.back.postLogoutRedirectUri }),
	...(request.back.state === undefined ? {} : { state: request.back.state }),
});

/** The return a token's claims carry, its client and its time, read back only as strings and a number. */
export const carriedFrom = (claims: Readonly<Record<string, unknown>> | undefined): Carried => {
	const uri = typeof claims?.back === "string" ? claims.back : undefined;
	const state = typeof claims?.state === "string" ? { state: claims.state } : {};
	const client = typeof claims?.client === "string" ? { client: claims.client } : {};
	const exp = typeof claims?.exp === "number" ? { exp: claims.exp } : {};
	const back = uri === undefined ? {} : { postLogoutRedirectUri: uri, ...state };
	return { back, ...client, ...exp };
};

/**
 * Claims the provider signed as `type` for `audience`, from `issuer`, not yet expired; none
 * otherwise. `keys` checks the signature, the type and the key alone; the claims are checked here.
 */
export async function heldClaims(
	p: Pick<CarriedParts, "keys" | "issuer" | "now">,
	token: string | undefined,
	type: string,
	audience: string,
) {
	if (!token) return undefined;
	const verified = await p.keys.verify(token, type);
	if (verified.kind !== "valid") return undefined;
	const { iss, aud, exp } = verified.claims;
	if (iss !== p.issuer || aud !== audience) return undefined;
	const now = Math.floor(p.now() / 1000);
	if (typeof exp !== "number" || !Number.isFinite(exp) || exp <= now) return undefined;
	return verified.claims;
}

/** Signs and checks carried requests, and holds a carried return to its client's registration now. */
export function carriedWith(p: CarriedParts) {
	/** The session a token of `type` for `audience` names and what it carries, where it holds. */
	const boundTo = async (token: string | undefined, type: string, audience: string) => {
		const claims = await heldClaims(p, token, type, audience);
		const sid = claims?.sid;
		if (typeof sid !== "string" || sid === "") return undefined;
		return { sid, ...carriedFrom(claims) };
	};
	/** A carried request and its time, where it holds. */
	const read = (token: string | undefined) => boundTo(token, carriedType, p.logoutUrl);
	return {
		/** A request `ending` checked, signed to be carried in the browser's URL. */
		carry: (request: CarriedRequest): Promise<string> => {
			const exp = Math.floor(p.now() / 1000) + p.withinSeconds;
			const at = { iss: p.issuer, aud: p.logoutUrl, exp };
			return p.keys.sign({ ...at, sid: request.sid, ...carriedClaims(request) }, carriedType);
		},
		read,
		boundTo,
		/** The request a token carries, where it holds. */
		carried: async (token: string | undefined): Promise<CarriedRequest | undefined> => {
			const found = await read(token);
			if (found === undefined) return undefined;
			const { exp: _, ...request } = found;
			return request;
		},
		/**
		 * The return, held to its client's registration as it is now: none where the client is gone or
		 * no longer registers it, never taken on what was registered when it was carried.
		 */
		current: async (request: Pick<Carried, "client" | "back">): Promise<LogoutReturn> => {
			const uri = request.back.postLogoutRedirectUri;
			if (uri === undefined) return request.back;
			if (request.client === undefined) return {};
			return returnsTo(await p.clients.find(request.client), uri) ? request.back : {};
		},
	};
}
