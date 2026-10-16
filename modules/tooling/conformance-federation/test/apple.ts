import { createHash, type KeyObject } from "node:crypto";
import { fakeHttp, type Scripted } from "@mod/conformance";
import { exportJWK, generateKeyPair, type JWK, jwtVerify, SignJWT } from "jose";

const issuer = "https://appleid.apple.com";

/** How the fake Apple answers one authorization. */
export interface AppleAuthorized {
	readonly subject: string;
	/** Signs the id_token with a key it never published. */
	readonly forged?: boolean;
	/** The nonce the id_token carries, in place of the one asked for. */
	readonly nonce?: string;
	/** The `user` field Apple posts on a first authorization. */
	readonly user?: string;
}

interface Granted extends AppleAuthorized {
	readonly asked: string;
	readonly challenge: string;
	readonly redirectUri: string;
	used?: boolean;
}

/**
 * Sign in with Apple on plain http at loopback, for the scenes: it answers in a posted form, takes
 * the client's fixed secret or one the team's key signs (checked with the team's public key), and
 * signs id_tokens with the one key its key set publishes, which `rotate` replaces.
 */
export async function fakeApple(client: {
	id: string;
	secret: string;
	team: { id: string; publicKey: KeyObject };
}) {
	const forger = await generateKeyPair("RS256", { extractable: true });
	let kid = 0;
	let current: { kid: string; key: CryptoKey; jwk: JWK };
	const rotate = async () => {
		const pair = await generateKeyPair("RS256", { extractable: true });
		const named = `apple-${++kid}`;
		const jwk = { ...(await exportJWK(pair.publicKey)), kid: named, use: "sig", alg: "RS256" };
		current = { kid: named, key: pair.privateKey, jwk };
	};
	await rotate();
	const codes = new Map<string, Granted>();
	const tokenCalls: string[] = [];
	const secrets: ("fixed" | "signed")[] = [];
	let n = 0;
	/** How the client authenticated: its fixed secret, or a secret its team signed for Apple. */
	const authenticated = async (form: URLSearchParams) => {
		const secret = form.get("client_secret") ?? "";
		if (form.get("client_id") !== client.id) return undefined;
		if (secret === client.secret) return "fixed";
		try {
			await jwtVerify(secret, client.team.publicKey, {
				algorithms: ["ES256"],
				issuer: client.team.id,
				subject: client.id,
				audience: issuer,
			});
			return "signed";
		} catch {
			return undefined;
		}
	};
	const token = async (form: URLSearchParams): Promise<Scripted> => {
		const by = await authenticated(form);
		if (!by) return { status: 400, json: { error: "invalid_client" } };
		const code = form.get("code") ?? "";
		tokenCalls.push(code);
		const granted = codes.get(code);
		const challenge = createHash("sha256")
			.update(form.get("code_verifier") ?? "")
			.digest("base64url");
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
		secrets.push(by);
		const now = Math.floor(Date.now() / 1000);
		const idToken = await new SignJWT({ nonce: granted.nonce ?? granted.asked })
			.setProtectedHeader({ alg: "RS256", kid: current.kid })
			.setIssuer(issuer)
			.setSubject(granted.subject)
			.setAudience(client.id)
			.setIssuedAt(now)
			.setExpirationTime(now + 600)
			.sign(granted.forged ? forger.privateKey : current.key);
		return {
			json: {
				access_token: `apple-access-${code}`,
				token_type: "Bearer",
				expires_in: 3600,
				refresh_token: `apple-refresh-${code}`,
				id_token: idToken,
			},
		};
	};
	const fake = await fakeHttp((asked) => {
		if (asked.path === "/auth/keys") return { json: { keys: [current.jwk] } };
		if (asked.path === "/auth/token" && asked.method === "POST") {
			return token(new URLSearchParams(asked.body));
		}
		return { status: 404, json: { error: "not_found" } };
	});
	return {
		base: fake.base,
		/** The token requests made, by the code they carried. */
		tokenCalls,
		/** How each code exchanged was paid for. */
		secrets,
		/** Signs from now on with a new key, and publishes only that one. */
		rotate,
		/**
		 * Authorizes the request a start sent the browser to, and answers the form Apple would post
		 * back: the code and state, and the user's name where given.
		 */
		authorize(location: string, as: AppleAuthorized): URLSearchParams {
			const asked = new URL(location).searchParams;
			if (
				asked.get("client_id") !== client.id ||
				asked.get("code_challenge_method") !== "S256" ||
				asked.get("response_mode") !== "form_post"
			) {
				throw new Error(`not an authorization request Apple takes: ${location}`);
			}
			const code = `apple-code-${++n}`;
			codes.set(code, {
				...as,
				asked: asked.get("nonce") ?? "",
				challenge: asked.get("code_challenge") ?? "",
				redirectUri: asked.get("redirect_uri") ?? "",
			});
			return new URLSearchParams({
				code,
				state: asked.get("state") ?? "",
				...(as.user === undefined ? {} : { user: as.user }),
			});
		},
		stop: () => fake.stop(),
	};
}
