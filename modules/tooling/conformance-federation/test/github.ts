import { createHash } from "node:crypto";
import { fakeHttp } from "@mod/conformance";

interface Granted {
	readonly id: number;
	readonly challenge: string;
	readonly redirectUri: string;
	used?: boolean;
}

/**
 * GitHub's OAuth on plain http at loopback, for the scenes: it hands out codes for the
 * authorizations the scene makes, answers a refused code with 200 and an error as GitHub does, and
 * tells the user's numeric id for the access token it gave.
 */
export async function fakeGithub(client: { id: string; secret: string }) {
	const codes = new Map<string, Granted>();
	const tokens = new Map<string, number>();
	const tokenCalls: string[] = [];
	let n = 0;
	const fake = await fakeHttp((asked) => {
		if (asked.path === "/login/oauth/access_token" && asked.method === "POST") {
			const form = new URLSearchParams(asked.body);
			const code = form.get("code") ?? "";
			tokenCalls.push(code);
			const granted = codes.get(code);
			const challenge = createHash("sha256")
				.update(form.get("code_verifier") ?? "")
				.digest("base64url");
			if (
				form.get("client_id") !== client.id ||
				form.get("client_secret") !== client.secret ||
				!granted ||
				granted.used ||
				form.get("redirect_uri") !== granted.redirectUri ||
				challenge !== granted.challenge
			) {
				return { json: { error: "bad_verification_code" } };
			}
			granted.used = true;
			const token = `gho_${++n}`;
			tokens.set(token, granted.id);
			return { json: { access_token: token, token_type: "bearer", scope: "read:user" } };
		}
		if (asked.path === "/user") {
			// GitHub's API refuses a request that names no User-Agent.
			if (!asked.headers["user-agent"]) {
				return {
					status: 403,
					json: { message: "Request forbidden: a User-Agent header is required" },
				};
			}
			// Only in the Authorization header, under the Bearer scheme (RFC 6750 §2.1): any other way of
			// presenting it is no credential here.
			const bearer = /^Bearer (\S+)$/.exec(asked.headers.authorization ?? "");
			const id = bearer ? tokens.get(bearer[1] as string) : undefined;
			return id === undefined
				? { status: 401, json: { message: "Bad credentials" } }
				: { json: { id, login: `user-${id}` } };
		}
		return { status: 404, json: { message: "Not Found" } };
	});
	return {
		base: fake.base,
		tokenCalls,
		/** Authorizes the request a start sent the browser to, answering the callback query. */
		authorize(location: string, id: number): URLSearchParams {
			const asked = new URL(location).searchParams;
			if (asked.get("client_id") !== client.id || asked.get("code_challenge_method") !== "S256") {
				throw new Error(`not an authorization request GitHub takes: ${location}`);
			}
			const code = `gh-code-${++n}`;
			codes.set(code, {
				id,
				challenge: asked.get("code_challenge") ?? "",
				redirectUri: asked.get("redirect_uri") ?? "",
			});
			return new URLSearchParams({ code, state: asked.get("state") ?? "" });
		},
		stop: () => fake.stop(),
	};
}
