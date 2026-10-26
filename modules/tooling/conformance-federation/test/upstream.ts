import { createHash } from "node:crypto";
import { fakeHttp, type Scripted } from "@mod/conformance";
import { exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";

/** How the fake upstream answers one authorization. */
export interface Authorized {
	readonly subject: string;
	/** Signs the id_token with a key it never published. */
	readonly forged?: boolean;
	/** Signs the id_token with a published key of another algorithm. */
	readonly elliptic?: boolean;
	/** The nonce the id_token carries, in place of the one asked for. */
	readonly nonce?: string;
	/** When the user logged in, in epoch seconds, as `auth_time` says. */
	readonly authTime?: number;
	/** What its token endpoint says of the tokens, where a scene sets it; with a refresh token unless told not to. */
	readonly tokens?: {
		readonly accessToken?: string;
		readonly tokenType?: unknown;
		readonly expiresIn?: unknown;
		readonly scope?: string;
		readonly refresh?: false;
	};
}

interface Granted extends Authorized {
	readonly asked: string;
	readonly challenge: string;
	readonly redirectUri: string;
	used?: boolean;
}

/** Where a fake upstream answers, and the issuer it names: its own base unless one is given. */
export interface UpstreamShape {
	readonly issuer?: string;
	readonly authorize: string;
	readonly token: string;
	readonly jwks: string;
	/** Answers the user's subject for an access token it gave. */
	readonly userinfo?: string;
}

const ownShape: UpstreamShape = {
	authorize: "/authorize",
	token: "/token",
	jwks: "/jwks",
	userinfo: "/userinfo",
};
/** Google's paths, on its fixed issuer. */
export const googleShape: UpstreamShape = {
	issuer: "https://accounts.google.com",
	authorize: "/o/oauth2/v2/auth",
	token: "/token",
	jwks: "/oauth2/v3/certs",
	userinfo: "/oauth2/v3/userinfo",
};

/**
 * An upstream OpenID Connect IdP on plain http at loopback, or behind the https front at `origin`, for the scenes: it publishes its
 * description (when it is its own issuer) and keys, hands out codes for the authorizations the
 * scene makes, and answers its token endpoint as a real one would, checking the client (by HTTP
 * Basic or in the form), the redirect URI and the PKCE verifier. It answers refreshes as the scene
 * scripts them, and names its end of session where asked.
 */
export async function fakeUpstream(
	client: { id: string; secret: string },
	options: {
		readonly shape?: UpstreamShape;
		readonly endSession?: boolean;
		/** The origin it is reached by, an https front before it say, in place of its own base. */
		readonly origin?: string;
		/** The origin its description names UserInfo at, where not the one it is reached by. */
		readonly userinfoOrigin?: string;
	} = {},
) {
	const shape = options.shape ?? ownShape;
	const signing = await generateKeyPair("RS256", { extractable: true });
	const forger = await generateKeyPair("RS256", { extractable: true });
	const ec = await generateKeyPair("ES256", { extractable: true });
	const published: JWK[] = [
		{ ...(await exportJWK(signing.publicKey)), kid: "up-1", use: "sig", alg: "RS256" },
		{ ...(await exportJWK(ec.publicKey)), kid: "up-ec", use: "sig", alg: "ES256" },
	];
	const codes = new Map<string, Granted>();
	const accessed = new Map<string, string>();
	const tokenCalls: string[] = [];
	/** Refresh tokens it gave out, by token, and the scope each was given with. */
	const refreshTokens = new Map<string, string>();
	/** What the next refreshes answer, in turn; past them, new tokens with no scope said. */
	const refreshAnswers: Scripted[] = [];
	const refreshCalls: string[] = [];
	const idTokens: string[] = [];
	/** What the next UserInfo requests answer, in turn, each as given or when it comes; past them, the subject and its name. */
	const userinfoAnswers: (Scripted | (() => Promise<Scripted>))[] = [];
	const userinfoCalls: string[] = [];
	let n = 0;
	const refresh = (form: URLSearchParams): Scripted => {
		const presented = form.get("refresh_token") ?? "";
		refreshCalls.push(presented);
		const scripted = refreshAnswers.shift();
		if (scripted) return scripted;
		if (!refreshTokens.has(presented)) return { status: 400, json: { error: "invalid_grant" } };
		const next = `upstream-refresh-${++n}`;
		refreshTokens.set(next, refreshTokens.get(presented) ?? "");
		return {
			json: {
				access_token: `upstream-access-${n}`,
				token_type: "Bearer",
				expires_in: 300,
				refresh_token: next,
			},
		};
	};
	const basic = `Basic ${Buffer.from(`${encodeURIComponent(client.id)}:${encodeURIComponent(client.secret)}`).toString("base64")}`;
	const token = async (
		form: URLSearchParams,
		authorization: string | undefined,
	): Promise<Scripted> => {
		const inForm =
			form.get("client_id") === client.id && form.get("client_secret") === client.secret;
		if (authorization !== basic && !inForm) {
			return { status: 401, json: { error: "invalid_client" } };
		}
		if (form.get("grant_type") === "refresh_token") return refresh(form);
		const code = form.get("code") ?? "";
		tokenCalls.push(code);
		const granted = codes.get(code);
		const verifier = form.get("code_verifier") ?? "";
		const challenge = createHash("sha256").update(verifier).digest("base64url");
		if (
			!granted ||
			granted.used ||
			form.get("grant_type") !== "authorization_code" ||
			form.get("redirect_uri") !== granted.redirectUri ||
			challenge !== granted.challenge
		) {
			return { status: 400, json: { error: "invalid_grant" } };
		}
		granted.used = true;
		const now = Math.floor(Date.now() / 1000);
		const [alg, kid, key] = granted.elliptic
			? ["ES256", "up-ec", ec.privateKey]
			: ["RS256", "up-1", granted.forged ? forger.privateKey : signing.privateKey];
		const idToken = await new SignJWT({
			nonce: granted.nonce ?? granted.asked,
			...(granted.authTime === undefined ? {} : { auth_time: granted.authTime }),
		})
			.setProtectedHeader({ alg, kid })
			.setIssuer(issuer)
			.setSubject(granted.subject)
			.setAudience(client.id)
			.setIssuedAt(now)
			.setExpirationTime(now + 300)
			.sign(key);
		idTokens.push(idToken);
		const said = granted.tokens ?? {};
		const scope = said.scope ?? "openid";
		const refreshToken = `upstream-refresh-${++n}`;
		if (said.refresh !== false) refreshTokens.set(refreshToken, scope);
		const accessToken = said.accessToken ?? `upstream-access-${code}`;
		accessed.set(accessToken, granted.subject);
		return {
			json: {
				access_token: accessToken,
				token_type: "tokenType" in said ? said.tokenType : "Bearer",
				expires_in: "expiresIn" in said ? said.expiresIn : 300,
				id_token: idToken,
				scope,
				...(said.refresh === false ? {} : { refresh_token: refreshToken }),
			},
		};
	};
	const fake = await fakeHttp((asked, own) => {
		const base = options.origin ?? own;
		if (asked.path === "/.well-known/openid-configuration" && !shape.issuer) {
			return {
				json: {
					issuer: base,
					authorization_endpoint: `${base}${shape.authorize}`,
					token_endpoint: `${base}${shape.token}`,
					jwks_uri: `${base}${shape.jwks}`,
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["RS256"],
					code_challenge_methods_supported: ["S256"],
					token_endpoint_auth_methods_supported: ["client_secret_basic"],
					authorization_response_iss_parameter_supported: true,
					...(options.endSession ? { end_session_endpoint: `${base}/logout` } : {}),
					...(shape.userinfo
						? { userinfo_endpoint: `${options.userinfoOrigin ?? base}${shape.userinfo}` }
						: {}),
				},
			};
		}
		if (asked.path === shape.jwks) return { json: { keys: published } };
		if (asked.path === shape.token && asked.method === "POST") {
			return token(new URLSearchParams(asked.body), asked.headers.authorization);
		}
		if (asked.path === shape.userinfo) {
			const subject = accessed.get((asked.headers.authorization ?? "").replace(/^Bearer /, ""));
			userinfoCalls.push(subject ?? "");
			if (subject === undefined) return { status: 401, json: { error: "invalid_token" } };
			const next = userinfoAnswers.shift();
			if (typeof next === "function") return next();
			return next ?? { json: { sub: subject, name: `${subject} upstream` } };
		}
		return { status: 404, json: { error: "not_found" } };
	});
	const issuer = shape.issuer ?? options.origin ?? fake.base;
	return {
		/** Where it listens. */
		base: fake.base,
		/** The issuer it names. */
		issuer,
		/** The token requests made, by the code they carried. */
		tokenCalls,
		/** The refresh requests made, by the refresh token they carried. */
		refreshCalls,
		/** The id_tokens it gave, in order. */
		idTokens,
		/** The UserInfo requests made, by the subject of the access token they carried. */
		userinfoCalls,
		/** The next UserInfo answers as given, before any already set. */
		answerUserinfo: (...answers: (Scripted | (() => Promise<Scripted>))[]) => {
			userinfoAnswers.push(...answers);
		},
		/** The next refresh answers as given, before any already set. */
		answerRefresh: (...answers: Scripted[]) => {
			refreshAnswers.push(...answers);
		},
		/**
		 * Authorizes the request a start sent the browser to, as the user would at the upstream, and
		 * answers the callback query the upstream would send the browser back with.
		 */
		authorize(location: string, as: Authorized): URLSearchParams {
			const asked = new URL(location).searchParams;
			if (asked.get("client_id") !== client.id || asked.get("code_challenge_method") !== "S256") {
				throw new Error(`not an authorization request this upstream takes: ${location}`);
			}
			const code = `code-${++n}`;
			codes.set(code, {
				...as,
				asked: asked.get("nonce") ?? "",
				challenge: asked.get("code_challenge") ?? "",
				redirectUri: asked.get("redirect_uri") ?? "",
			});
			return new URLSearchParams({ code, state: asked.get("state") ?? "", iss: issuer });
		},
		stop: () => fake.stop(),
	};
}
