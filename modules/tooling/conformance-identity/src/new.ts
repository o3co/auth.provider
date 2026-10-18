import { randomBytes, scryptSync } from "node:crypto";
import { type NewPart, onNew, type PatternPart } from "@mod/conformance";
import bcrypt from "bcryptjs";
import { type IdentityPart, identityArea, type LedgerScene } from "./area.ts";
import { ledgerParty, unledgered } from "./ledger.ts";
import { statedWhereJudged } from "./pattern.ts";

/** A scrypt hash in the users module's form, with the least work it allows. */
function scryptHash(password: string): string {
	const salt = randomBytes(16);
	const key = scryptSync(password, salt, 32, { N: 2 ** 10, r: 8, p: 1 });
	const b64 = (bytes: Buffer) => bytes.toString("base64").replace(/=+$/, "");
	return `$scrypt$ln=10,r=8,p=1$${b64(salt)}$${b64(key)}`;
}

/** The ledger's sections: users-http, and outbound naming its host (as plain http at loopback). */
function ledgerConfig(ledger: LedgerScene) {
	const at = new URL(ledger.verifyUrl);
	return {
		"users-http": {
			"verify-url": ledger.verifyUrl,
			credential: ledger.credential,
			...(ledger.timeoutMs ? { timeout: `${ledger.timeoutMs}ms` } : {}),
		},
		outbound: {
			allow: [at.hostname],
			"plain-loopback": at.protocol === "http:" ? [at.host] : [],
		},
	};
}

const setUp = (part: IdentityPart, _: unknown, modules: readonly string[]): NewPart => ({
	modules: [
		"@mod/users",
		"@mod/session-lifecycle",
		"@mod/csrf",
		"@mod/subject-revocation",
		"@mod/rate-limit",
		"@mod/login-gates",
		"@mod/login-password",
		"@mod/audit",
		"@mod/logout",
		...(part.ledger ? ["@mod/outbound", "@mod/users-http"] : []),
	],
	store: "volatile",
	// Mail, where users brings it along, sends nothing in a scene.
	...(modules.includes("@mod/mail") ? { fallback: { mail: { "accept-unsent": true } } } : {}),
	config: {
		http: {
			"trusted-proxies": ["127.0.0.1"],
			"public-origin": part.origin,
			...(part.corsOrigins ? { "cors-origins": part.corsOrigins } : {}),
		},
		users: {
			registered: part.users.map((u) => ({
				identifier: u.identifier,
				...(u.subject ? { subject: u.subject } : {}),
				"password-hash": u.bcrypt ? bcrypt.hashSync(u.password, 4) : scryptHash(u.password),
				...(u.upstream ? { upstream: [u.upstream] } : {}),
				...(u.email || u.emailVerified !== undefined
					? {
							attributes: {
								...(u.email ? { email: u.email } : {}),
								...(u.emailVerified === undefined ? {} : { email_verified: u.emailVerified }),
							},
						}
					: {}),
			})),
		},
		"login-gates": { "return-targets": part.login?.returnTargets ?? [] },
		"login-password": {
			...(part.login?.attempts ? { attempts: part.login.attempts } : {}),
			...(part.login?.windowSeconds ? { window: `${part.login.windowSeconds}s` } : {}),
			...(part.login?.accountAttempts ? { "account-attempts": part.login.accountAttempts } : {}),
			...(part.login?.accountWindowSeconds
				? { "account-window": `${part.login.accountWindowSeconds}s` }
				: {}),
			...(part.login?.accountMaxWaitSeconds
				? { "account-max-wait": `${part.login.accountMaxWaitSeconds}s` }
				: {}),
		},
		...(part.ledger ? ledgerConfig(part.ledger) : {}),
	},
});

/** On an app taking users from a ledger, which refuses them in the settings, a fake ledger holds them. */
export function onPattern(
	given: IdentityPart,
	scene: unknown,
	modules: readonly string[],
): PatternPart {
	const part = { ...given, users: statedWhereJudged(given.users, modules) };
	const set = setUp(part, scene, modules);
	if (!modules.includes("@mod/users-http") || part.ledger || part.users.length === 0) return set;
	const reason = unledgered(part.users);
	if (reason) return { leaveOut: reason };
	const { users: _users, ...config } = set.config ?? {};
	return { ...set, config, party: () => ledgerParty(part.users) };
}

onNew(identityArea, setUp, onPattern);
