import {
	assemble,
	defineModule,
	isUnavailable,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import secretHashModule from "@mod/secret-hash/module";
import { type AuthContext, sessions } from "@mod/session";
import { stubSessions } from "@mod/session/testing";
import { type AttributesAnswer, subjectAttributes } from "@mod/subject-attributes";
import subjectAttributesModule from "@mod/subject-attributes/module";
import { type IssuanceRequest, tokens } from "@mod/tokens";
import { tokensStandIn } from "@mod/tokens/testing";
import { ledgers, userAttribute } from "@mod/users";
import usersModule from "@mod/users/module";
import { memoryUsersStores, testUser, usersConfig } from "@mod/users/testing";
import { describe, expect, it } from "vitest";
import verifiedEmail from "../src/module.ts";

const runtime = quietRuntime();
const grant = { subject: "s-alice", issuedTo: "c", audience: ["api"], scope: [] };
const asked = (grantType: string, session?: string): IssuanceRequest => ({
	grant,
	grantType,
	...(session === undefined ? {} : { session }),
});
const refused = {
	kind: "refused",
	policy: "verified-email",
	reason: "email_not_verified",
	description: "email address is not verified",
};
/** An answer users vouches for. */
const known = (attributes: Record<string, unknown>): AttributesAnswer => ({
	kind: "known",
	vouched: true,
	attributes,
});
const verified = (value: unknown) => ({ [userAttribute.emailVerified]: value });

/** Tokens with the policy over a reader answering `answer`; `reads` lists each subject and handle read. */
async function over(answer: () => Promise<AttributesAnswer>) {
	const reads: (readonly [string, string | undefined])[] = [];
	const reader = defineModule({ name: "subject-attributes", takes: [] }, (m) => [
		m.provide(subjectAttributes).by(() => ({
			of: async (subject, handle) => {
				reads.push([subject, handle]);
				return answer();
			},
		})),
	]);
	const input = {
		modules: [tokensStandIn(), reader, verifiedEmail],
		config: kernelConfig(),
		runtime,
	};
	const app = await assemble(input);
	return { admits: (request: IssuanceRequest) => app.get(tokens).admits(request), reads, input };
}

describe("what counts as verified", () => {
	it("allows a subject users states verified, reading its subject and session", async () => {
		const t = await over(async () => known(verified(true)));
		expect(await t.admits(asked("authorization_code", "h1"))).toEqual({ kind: "allowed" });
		expect(t.reads).toEqual([["s-alice", "h1"]]);
	});

	it.each([
		["false", verified(false)],
		["absent", {}],
		["the string true", verified("true")],
		["a number", verified(1)],
	])("refuses users' verified value when %s", async (_, attributes) => {
		const t = await over(async () => known(attributes));
		expect(await t.admits(asked("authorization_code", "h1"))).toEqual(refused);
	});

	it("refuses a word users does not vouch for that the email is verified", async () => {
		const t = await over(async () => ({
			kind: "known",
			vouched: false,
			attributes: verified(true),
		}));
		expect(await t.admits(asked("authorization_code", "h1"))).toEqual(refused);
	});

	it("refuses a subject nobody can answer for", async () => {
		const t = await over(async () => ({ kind: "unknown" }));
		expect(await t.admits(asked("session", "h1"))).toEqual(refused);
	});

	it("is unavailable, never a refusal, when the attributes cannot be read", async () => {
		const t = await over(async () => {
			throw new Unavailable("users");
		});
		await expect(t.admits(asked("authorization_code", "h1"))).rejects.toSatisfy(isUnavailable);
	});
});

describe("which grants it judges", () => {
	it("lets client_credentials by unread", async () => {
		const t = await over(async () => ({ kind: "unknown" }));
		expect(await t.admits(asked("client_credentials"))).toEqual({ kind: "allowed" });
		expect(t.reads).toEqual([]);
	});

	it("lets an issuance its issuer marks continuing by unread, whatever its grant type", async () => {
		const t = await over(async () => ({ kind: "unknown" }));
		const continuing = { ...asked("refresh_token"), continuing: true as const };
		expect(await t.admits(continuing)).toEqual({ kind: "allowed" });
		expect(t.reads).toEqual([]);
	});

	it.each([
		"refresh_token",
		"authorization_code",
		"session",
		"urn:ietf:params:oauth:grant-type:jwt-bearer",
		"urn:ietf:params:oauth:grant-type:device_code",
		"urn:ietf:params:oauth:grant-type:token-exchange",
		"urn:o3co:oauth:grant-type:webauthn",
		"urn:example:a-later-grant",
	])("judges %s", async (grantType) => {
		const t = await over(async () => ({ kind: "unknown" }));
		expect(await t.admits(asked(grantType))).toEqual(refused);
		expect(t.reads).toEqual([["s-alice", undefined]]);
	});
});

describe("over users and the session's login", () => {
	const login = (source: string): AuthContext => ({
		subject: "s-alice",
		amr: ["pwd"],
		authenticatedAt: 0,
		attributes: { source, values: { [userAttribute.emailVerified]: true } },
	});
	/** A ledger that cannot look users up by subject. */
	const unanswering = defineModule({ name: "ledger", takes: [] }, (m) => [
		m.contribute(ledgers).by(() => ({
			verify: async () => ({ kind: "none" }),
			bySubject: async () => ({ kind: "unanswerable" }),
		})),
	]);
	const boot = (parts: { users: readonly Module[]; config: object; login?: AuthContext }) =>
		assemble({
			modules: [
				tokensStandIn(),
				memoryUsersStores().module,
				...parts.users,
				secretHashModule,
				defineModule({ name: "sessions", takes: [tokens] }, (m) => [
					// Sessions that reach tokens as they are built, as a composition's closing tokens does.
					m.provide(sessions).by(async (c) => {
						await c.get(tokens);
						const login = parts.login;
						return stubSessions({
							entryOf: async (handle) =>
								handle === "h1" && login !== undefined
									? { kind: "entered", session: { id: handle, context: login }, endsAt: 1 }
									: { kind: "absent" },
						});
					}),
				]),
				subjectAttributesModule,
				verifiedEmail,
			],
			config: { ...kernelConfig(), ...parts.config },
			runtime,
		});
	const registered = (attributes: Record<string, unknown>) =>
		usersConfig([testUser("alice", "pw", { subject: "s-alice", attributes })]);

	it("allows a registered user users states verified", async () => {
		const app = await boot({ users: [usersModule], config: registered(verified(true)) });
		expect(await app.get(tokens).admits(asked("session", "h1"))).toEqual({ kind: "allowed" });
	});

	it("refuses a registered user users does not state verified, though the session's login says so", async () => {
		const app = await boot({ users: [usersModule], config: registered({}), login: login("users") });
		expect(await app.get(tokens).admits(asked("session", "h1"))).toEqual(refused);
	});

	it("refuses a subject users holds no user for", async () => {
		const app = await boot({
			users: [usersModule],
			config: usersConfig([]),
			login: login("users"),
		});
		expect(await app.get(tokens).admits(asked("session", "h1"))).toEqual(refused);
	});

	it("reads a ledger's login when users cannot look the subject up, and only under users", async () => {
		const users = [usersModule, unanswering];
		const ledger = await boot({ users, config: {}, login: login("users") });
		expect(await ledger.get(tokens).admits(asked("session", "h1"))).toEqual({ kind: "allowed" });
		const upstream = await boot({ users, config: {}, login: login("federation:acme") });
		expect(await upstream.get(tokens).admits(asked("session", "h1"))).toEqual(refused);
	});
});

it("takes all it names", async () => {
	const { input } = await over(async () => known(verified(true)));
	expect(await takesUnused(input)).toEqual({});
});
