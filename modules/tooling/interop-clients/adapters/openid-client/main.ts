// The openid-client adapter: one flow per run, told on its first input line, done with the library's
// own calls; each browser step is asked of the driver, and the result is what the library gave back.
// It trusts the front's certificate its instruction gives, and nothing else: no public root either.
import { createInterface } from "node:readline";
import * as client from "openid-client";
import { Agent, fetch } from "undici";

const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
const read = async (): Promise<Record<string, unknown>> =>
	JSON.parse(String((await lines.next()).value));
const write = (value: unknown) => process.stdout.write(`${JSON.stringify(value)}\n`);
const ask = async (question: Record<string, unknown>) => {
	write(question);
	return read();
};

interface Client {
	readonly id: string;
	readonly secret?: string;
	readonly method: "client_secret_basic" | "client_secret_post" | "none" | "private_key_jwt";
	readonly privateJwk?: JsonWebKey & { kid?: string; alg?: string };
}

interface Instruction {
	readonly flow: string;
	readonly issuer: string;
	/** The front's certificate, as PEM: the one certificate the adapter trusts. */
	readonly ca: string;
	readonly client: Client;
	readonly redirectUri?: string;
	readonly scope?: string;
}

async function authOf(c: Client): Promise<client.ClientAuth> {
	if (c.method === "client_secret_basic") return client.ClientSecretBasic(c.secret ?? "");
	if (c.method === "client_secret_post") return client.ClientSecretPost(c.secret ?? "");
	if (c.method === "none") return client.None();
	const jwk = c.privateJwk ?? {};
	const key = await crypto.subtle.importKey(
		"jwk",
		jwk,
		{ name: "ECDSA", namedCurve: "P-256" },
		false,
		["sign"],
	);
	return client.PrivateKeyJwt({ key, kid: jwk.kid });
}

/** The library's fetch, over a connection that trusts the instruction's certificate alone. */
function trusting(ca: string): client.CustomFetch {
	const dispatcher = new Agent({ connect: { ca: [ca] } });
	return (url, options) => fetch(url, { ...options, dispatcher }) as unknown as Promise<Response>;
}

/** An endpoint the discovery names over anything but https fails the flow before any request is sent there. */
function refuseInsecure(metadata: Record<string, unknown>) {
	for (const [key, value] of Object.entries(metadata)) {
		if (!(key.endsWith("_endpoint") || key === "jwks_uri") || typeof value !== "string") continue;
		if (new URL(value).protocol !== "https:")
			throw Object.assign(new Error(`the discovery names ${key} ${value}, not https`), {
				error: "insecure",
			});
	}
}

async function configOf(i: Instruction) {
	const metadata = i.client.method === "none" ? {} : { client_secret: i.client.secret };
	const fetching = trusting(i.ca);
	const config = await client.discovery(
		new URL(i.issuer),
		i.client.id,
		metadata,
		await authOf(i.client),
		{
			[client.customFetch]: fetching,
		},
	);
	config[client.customFetch] = fetching;
	refuseInsecure(config.serverMetadata() as unknown as Record<string, unknown>);
	// The id token's signature is checked against the provider's keys, not taken on TLS's word.
	client.enableNonRepudiationChecks(config);
	return config;
}

/** The authorization code flow with PKCE, nonce and state, the browser's part asked of the driver. */
async function signIn(config: client.Configuration, i: Instruction) {
	const verifier = client.randomPKCECodeVerifier();
	const state = client.randomState();
	const nonce = client.randomNonce();
	const url = client.buildAuthorizationUrl(config, {
		redirect_uri: i.redirectUri ?? "",
		scope: i.scope ?? "openid",
		code_challenge: await client.calculatePKCECodeChallenge(verifier),
		code_challenge_method: "S256",
		state,
		nonce,
	});
	const { location } = await ask({ ask: "browse", url: url.href });
	return client.authorizationCodeGrant(config, new URL(String(location)), {
		pkceCodeVerifier: verifier,
		expectedState: state,
		expectedNonce: nonce,
		idTokenExpected: true,
	});
}

async function login(i: Instruction) {
	const config = await configOf(i);
	const tokens = await signIn(config, i);
	const claims = tokens.claims();
	const userinfo = await client.fetchUserInfo(config, tokens.access_token, claims?.sub ?? "");
	return {
		idToken: claims,
		userinfo,
		tokenType: tokens.token_type,
		scope: tokens.scope,
		refreshToken: tokens.refresh_token !== undefined,
	};
}

/** Signs in, refreshes once, then presents the refresh token it replaced again. */
async function refresh(i: Instruction) {
	const config = await configOf(i);
	const first = (await signIn(config, i)).refresh_token;
	if (first === undefined) throw new Error("the code's token answer held no refresh token");
	const renewed = await client.refreshTokenGrant(config, first);
	const replayed = await client.refreshTokenGrant(config, first).then(
		() => "taken",
		(error: { error?: string }) => error.error ?? "refused",
	);
	return {
		accessToken: renewed.access_token !== undefined,
		rotated: renewed.refresh_token !== undefined && renewed.refresh_token !== first,
		replayed,
	};
}

const flows: Record<string, (i: Instruction) => Promise<unknown>> = {
	login,
	"public-login": login,
	refresh,
};

const instruction = (await read()) as unknown as Instruction;
try {
	const flow = flows[instruction.flow];
	if (!flow) throw new Error(`no flow ${instruction.flow}`);
	write({ result: await flow(instruction) });
} catch (error) {
	const e = error as Error & { code?: string; error?: string; cause?: unknown };
	const cause = e.cause as
		| { status?: unknown; text?: () => Promise<string>; message?: unknown }
		| undefined;
	// What lies under the library's error: the answer it refused (its status and body's start), or the
	// failure beneath, such as a certificate the connection refused.
	const beneath =
		typeof cause?.status === "number" && typeof cause.text === "function"
			? ` (${cause.status}: ${(await cause.text()).slice(0, 300)})`
			: typeof cause?.message === "string"
				? ` (${cause.message})`
				: "";
	write({ error: { type: e.error ?? e.code ?? e.name, message: `${e.message}${beneath}` } });
}
process.exit(0);
