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
			...(ledger.upstreamUrl ? { "upstream-url": ledger.upstreamUrl } : {}),
		},
		outbound: {
			allow: [at.hostname],
			"plain-loopback": at.protocol === "http:" ? [at.host] : [],
		},
	};
}

const setUp = (part: IdentityPart): NewPart => ({
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
		...(part.revocations ? ["@mod/subject-revocation-http"] : []),
	],
	store: "volatile",
	// A scene's own ledger is the whole of its sections: no trial value joins them.
	...(part.ledger || part.revocations
		? {
				whole: [
					...(part.ledger ? ["users-http"] : []),
					...(part.revocations ? ["subject-revocation-http"] : []),
				],
			}
		: {}),
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
		...(part.recentAuthenticationSeconds
			? { "session-lifecycle": { "recent-authentication": `${part.recentAuthenticationSeconds}s` } }
			: {}),
		...(part.ledger ? ledgerConfig(part.ledger) : {}),
		...(part.revocations
			? {
					"subject-revocation-http": {
						credential: part.revocations.credential,
						sources: part.revocations.sources,
					},
				}
			: {}),
	},
});

/** On an app taking users from a ledger, which refuses them in the settings, a fake ledger holds them. */
export function onPattern(
	given: IdentityPart,
	_: unknown,
	modules: readonly string[],
): PatternPart {
	const part = { ...given, users: statedWhereJudged(given.users, modules) };
	const set = setUp(part);
	// An app keeping mfa's witness at a ledger asks it at a login: the ledger keeps it, whoever holds the users.
	const witness = modules.includes("@mod/mfa-witness-http");
	const witnessed = witness ? { whole: [...(set.whole ?? []), "mfa-witness-http"] } : {};
	if (!modules.includes("@mod/users-http") || part.ledger || part.users.length === 0) {
		return witness ? { ...set, ...witnessed, party: () => ledgerParty({ witness }) } : set;
	}
	const reason = unledgered(part.users);
	if (reason) return { leaveOut: reason };
	const { users: _users, ...config } = set.config ?? {};
	return { ...set, ...witnessed, config, party: () => ledgerParty({ users: part.users, witness }) };
}

onNew(identityArea, setUp, onPattern);
