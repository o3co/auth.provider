import type { ExternalJwt } from "@mod/external-jwt";
import { type Clock, type Log, Unavailable } from "@mod/kernel";
import { jsonObjectOf } from "@mod/outbound";
import {
	authorizationUrl,
	endSessionUrl,
	guarded,
	idTokenReaderOf,
	refreshAnswerOf,
	tokenAnswerOf,
	tokenPostOf,
} from "@mod/upstream-client";
import {
	type AuthorizationStart,
	type DelegatedExchange,
	type Upstream,
	type UpstreamRefresh,
	UpstreamRefused,
	type UpstreamTokens,
} from "@mod/upstreams";
import { z } from "zod";
import { type Described, describedBy, type Reach } from "./description/description.ts";
import { hostsOf, narrowerOf, type Settings, sentFor } from "./settings.ts";
import { userinfoOf } from "./userinfo/userinfo.ts";

/** The upstream's amr in its checked id_token, beyond what upstream-client reads. */
const amrClaim = z.looseObject({ amr: z.array(z.string()).optional() });

/**
 * Opens an OpenID Connect upstream; throws, refusing boot, wherever its description does not hold.
 * One whose description cannot be read at boot opens without it: each operation needing its
 * endpoints throws Unavailable until a read of it holds (`description`).
 */
export async function opened(
	s: Settings,
	reach: Reach,
	jwt: ExternalJwt,
	at: { readonly clock: Clock; readonly log: Log; readonly idp: string },
): Promise<Upstream> {
	const { outbound } = reach;
	const hosts = hostsOf(s);
	const from = sentFor(s);
	const skewMs = s["clock-skew"] * 1000;
	const client = s["client-id"];
	/** What the upstream does with a description's endpoints, built once it is read. */
	const partsOf = ({ endpoints, offersIss }: Described) => {
		const requireIss = !s["accept-missing-iss"] || offersIss;
		if (!requireIss) at.log.warn("idp-oidc.iss_not_required", { idp: at.idp });
		const idTokenOf = idTokenReaderOf(
			jwt,
			{
				issuer: s.issuer,
				client,
				jwks: { url: endpoints.jwks, ...narrowerOf(hosts, from.jwks) },
				algorithms: s.algorithms,
				skewMs,
				emailVerified: [true],
				what: "idp-oidc",
			},
			at.clock,
		);
		/**
		 * The upstream login an id_token says, once it holds for this client, login and access token;
		 * its profile completed by UserInfo where `userinfo` names it, the id_token checked first.
		 */
		const upstreamLoginOf = async (
			idToken: string,
			nonce: string,
			tokens: UpstreamTokens,
			userinfo: string | undefined,
		) => {
			const checked = await idTokenOf(idToken, nonce, tokens.accessToken);
			const read = amrClaim.safeParse(checked.claims);
			if (!read.success) throw new UpstreamRefused();
			const login =
				userinfo === undefined
					? checked.login
					: checked.withUserinfo(
							await userinfoOf(outbound, userinfo, tokens, narrowerOf(hosts, from.userinfo)),
						);
			return { ...login, amr: read.data.amr ?? [] };
		};
		/** Posts a grant to the token endpoint, with the client's secret as the operator says. */
		const granting = tokenPostOf(
			outbound,
			endpoints.token,
			{
				id: client,
				auth: s["token-auth"] === "client_secret_post" ? "form" : "basic",
				secret: async () => s["client-secret"],
			},
			narrowerOf(hosts, from.token),
		);
		/**
		 * The login and the tokens of a code; its scopes are what an answer without a scope stands for.
		 * UserInfo is read where `userinfo` names it: a login's code, never a delegation's.
		 */
		const exchanged = (code: DelegatedExchange, userinfo?: string) =>
			guarded(async () => {
				// Mix-up: an answer from another issuer is refused before its code is used.
				if (code.iss === undefined ? requireIss : code.iss !== s.issuer) {
					throw new UpstreamRefused();
				}
				const answer = await granting({
					grant_type: "authorization_code",
					code: code.code,
					redirect_uri: code.redirectUri,
					code_verifier: code.verifier,
					...(code.resource === undefined ? {} : { resource: code.resource }),
				});
				const { tokens, idToken } = tokenAnswerOf(jsonObjectOf(answer), code.scopes);
				if (!idToken) throw new UpstreamRefused();
				const login = await upstreamLoginOf(idToken, code.nonce, tokens, userinfo);
				return { ...login, tokens: { ...tokens, idToken } };
			});
		const refreshed = (refreshToken: string, scopes: readonly string[], resource?: string) =>
			guarded(async (): Promise<UpstreamRefresh> => {
				const answer = await granting({
					grant_type: "refresh_token",
					refresh_token: refreshToken,
					...(scopes.length > 0 ? { scope: scopes.join(" ") } : {}),
					...(resource === undefined ? {} : { resource }),
				});
				return refreshAnswerOf(answer, scopes, "idp-oidc");
			});
		return { endpoints, exchanged, refreshed };
	};
	type Parts = ReturnType<typeof partsOf>;
	const description = await describedBy(s, reach, hosts, at);
	/** The parts now, for what answers at once: Unavailable while the description is awaited. */
	let now: () => Parts;
	/** The parts, a read of the description awaited first where it is awaited. */
	let later: () => Promise<Parts>;
	if (description.kind === "read") {
		const parts = partsOf(description.described);
		now = () => parts;
		later = async () => parts;
	} else {
		let parts: Parts | undefined;
		const of = (described: Described) => {
			parts ??= partsOf(described);
			return parts;
		};
		now = () => {
			const described = description.now();
			if (!described) throw new Unavailable("idp-oidc description");
			return of(described);
		};
		later = async () => of(await description.when());
	}
	/** A start's own parameters: the nonce, and the browser's prompt and max age. */
	const asking = (start: AuthorizationStart, prompt: string | undefined) => ({
		nonce: start.nonce,
		...(prompt ? { prompt } : {}),
		...(start.maxAgeSeconds === undefined ? {} : { max_age: String(start.maxAgeSeconds) }),
	});
	// Awaited, whether it has one is known only once read: until then, it cannot tell.
	const offersEndSession =
		description.kind === "awaited" || description.described.endpoints.endSession !== undefined;
	return {
		issuer: s.issuer,
		clockSkewMs: skewMs,
		authorizationUrl: (start) =>
			authorizationUrl(
				now().endpoints.authorization,
				start,
				{ clientId: client, scopes: s.scopes },
				asking(start, start.prompt),
			),
		exchange: async (code) => {
			const parts = await later();
			return parts.exchanged({ ...code, scopes: s.scopes }, parts.endpoints.userinfo);
		},
		// The login's refresh passes no resource.
		refresh: async (refreshToken, scopes) => (await later()).refreshed(refreshToken, scopes),
		delegation: {
			authorizationUrl: (start) => {
				if (!start.scopes.includes("openid")) return { kind: "refused" };
				// Offline access is granted only where the user is asked (OpenID Connect Core §11).
				const consent = start.scopes.includes("offline_access") ? "consent" : undefined;
				const prompt = [start.prompt, consent].filter(Boolean).join(" ");
				return authorizationUrl(
					now().endpoints.authorization,
					start,
					{ clientId: client, scopes: start.scopes },
					{
						...asking(start, prompt),
						...(start.resource === undefined ? {} : { resource: start.resource }),
					},
				);
			},
			exchange: async (code: DelegatedExchange) => ({
				...(await (await later()).exchanged(code)),
				issuer: s.issuer,
			}),
			refresh: async (refreshToken, scopes, resource) =>
				(await later()).refreshed(refreshToken, scopes, resource),
		},
		...(offersEndSession
			? {
					endSession: (ending) => {
						const { endSession } = now().endpoints;
						return endSession === undefined
							? undefined
							: endSessionUrl(endSession, { ...ending, clientId: client });
					},
				}
			: {}),
	};
}
