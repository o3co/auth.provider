import { onLegacy } from "@mod/conformance-legacy";
import bcrypt from "bcryptjs";
import {
	type IdentityPart,
	identityArea,
	type LedgerScene,
	ledgerBesideUsers,
	ledgerRevocation,
	type UpstreamScene,
} from "./area.ts";

const legacyToken = (upstream: UpstreamScene) => `${upstream.idp}:${upstream.subject}`;

/** Users as the legacy file holds them: plain passwords, or bcrypt hashes where asked. */
function usersYaml(part: IdentityPart): string {
	const entries = part.users.map((u) => [
		u.identifier,
		{
			password: u.bcrypt ? bcrypt.hashSync(u.password, 4) : u.password,
			...(u.subject ? { id: u.subject } : {}),
			// The legacy file links an upstream identity as `<idp>:<upstream subject>`.
			...(u.upstream ? { token: legacyToken(u.upstream) } : {}),
			...(u.email ? { email: u.email } : {}),
			...(u.emailVerified === undefined ? {} : { emailVerified: u.emailVerified }),
		},
	]);
	return `${JSON.stringify(Object.fromEntries(entries))}\n`;
}

function loginSettings(part: IdentityPart): string {
	if (!part.login) return "";
	const lines = [`redirectAllowlist = ${JSON.stringify(part.login.returnTargets ?? [])}`];
	if (part.login.attempts || part.login.windowSeconds) {
		lines.push(
			`rateLimit.login { windowMs = ${(part.login.windowSeconds ?? 900) * 1000}, limit = ${part.login.attempts ?? 20} }`,
		);
	}
	return `session { ${lines.join("\n")} }\n`;
}

/** The origins whose pages may read cross-origin routes, where the legacy http module reads them. */
const corsSettings = (part: IdentityPart) =>
	part.corsOrigins
		? `http { cors { allowedOrigins = ${JSON.stringify(part.corsOrigins)} } }\n`
		: "";

/** The HTTP user repository in place of the users file; its token URL is required, and never asked here. */
const ledgerEnv = (ledger: LedgerScene) => ({
	ADAPTERS_USER_REPOSITORY: "http",
	REPOSITORIES_USER_HTTP_AUTHENTICATE_URL: ledger.verifyUrl,
	REPOSITORIES_USER_HTTP_AUTHENTICATE_BY_TOKEN_URL: new URL("/by-token", ledger.verifyUrl).href,
	REPOSITORIES_USER_HTTP_BEARER_TOKEN: ledger.credential,
	...(ledger.timeoutMs ? { REPOSITORIES_USER_HTTP_TIMEOUT: String(ledger.timeoutMs) } : {}),
});

onLegacy(identityArea, {
	map: (part) => ({
		env: { HTTP_TRUST_PROXY: "loopback", ...(part.ledger ? ledgerEnv(part.ledger) : {}) },
		settings: loginSettings(part) + corsSettings(part),
		files: { "users.yaml": usersYaml(part) },
	}),
	// The legacy build cannot be set up so that its login fails with its store, takes either
	// its users file or a ledger over HTTP, never both, and has no route a ledger revokes through.
	cannot: ["store-fault:login", ledgerBesideUsers, ledgerRevocation],
	// Ours matches a bcrypt password on all its bytes, answers a login that repeats a field as a
	// malformed request (400), and counts failed logins per identifier too, from any sender.
	differs: ["bcrypt-all-bytes", "repeated-field-login-400", "login-attempts-per-account"],
});
