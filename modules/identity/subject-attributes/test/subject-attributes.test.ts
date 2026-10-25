import { assemble, defineModule, isUnavailable, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, switchedModule, takesUnused, unavailableSwitch } from "@mod/kernel/testing";
import { loginSource } from "@mod/login-attributes";
import secretHashModule from "@mod/secret-hash/module";
import { type AuthContext, type Entry, type Sessions, sessions } from "@mod/session";
import { stubSessions } from "@mod/session/testing";
import { ledgers, type Users, userAttribute, users } from "@mod/users";
import usersModule from "@mod/users/module";
import { memoryUsersStores, testUser, usersConfig } from "@mod/users/testing";
import { describe, expect, it } from "vitest";
import { subjectAttributes, vouches } from "../src/contract.ts";
import reader from "../src/module.ts";

const runtime = quietRuntime();
const login = { email: "alice@login.example", [userAttribute.emailVerified]: true };
const context = (subject: string, source?: string): AuthContext => ({
	subject,
	amr: ["pwd"],
	authenticatedAt: 0,
	...(source ? { attributes: { source, values: login } } : {}),
});

/** A session short of a requirement at use. */
const short: Entry = { kind: "short", requirement: "mfa", answer: { error: "mfa_required" } };

/** Sessions by handle, entered with their context or as the entry given; `asked` lists each read. */
const sessionsOf = (byHandle: Record<string, AuthContext | Entry>, asked: string[] = []) =>
	defineModule({ name: "sessions", takes: [] }, (m) => [
		m.provide(sessions).by(() =>
			stubSessions({
				entryOf: async (handle, level) => {
					asked.push(level === undefined ? handle : `${handle}@${level}`);
					const found = byHandle[handle];
					if (found === undefined) return { kind: "absent" };
					if ("kind" in found) return found;
					return { kind: "entered", session: { id: handle, context: found }, endsAt: 1 };
				},
			}),
		),
	]);

/** A ledger that cannot look users up by subject. */
const unanswering = defineModule({ name: "ledger", takes: [] }, (m) => [
	m.contribute(ledgers).by(() => ({
		verify: async () => ({ kind: "none" }),
		bySubject: async () => ({ kind: "unanswerable" }),
	})),
]);

const boot = (parts: {
	readonly users?: Module[];
	readonly sessions: Module;
	readonly registered?: boolean;
}) =>
	assemble({
		modules: [
			memoryUsersStores().module,
			...(parts.users ?? [usersModule]),
			secretHashModule,
			parts.sessions,
			reader,
		],
		config: {
			...kernelConfig(),
			...(parts.registered === false
				? {}
				: usersConfig([
						testUser("alice", "pw", {
							subject: "s-alice",
							attributes: { [userAttribute.name]: "Alice", role: "x" },
						}),
					])),
		},
		runtime,
	});

describe("when users answers for the subject", () => {
	it("answers users' attributes alone, never reading the session", async () => {
		const asked: string[] = [];
		const app = await boot({ sessions: sessionsOf({ h: context("s-alice", "users") }, asked) });
		expect(await app.get(subjectAttributes).of("s-alice", "h")).toEqual({
			kind: "known",
			vouched: true,
			attributes: { [userAttribute.name]: "Alice", role: "x" },
		});
		expect(asked).toEqual([]);
	});

	it("answers users with no attributes for a subject with no user, never reading the session", async () => {
		const asked: string[] = [];
		const app = await boot({ sessions: sessionsOf({ h: context("s-bob", "users") }, asked) });
		expect(await app.get(subjectAttributes).of("s-bob", "h")).toEqual({
			kind: "known",
			vouched: true,
			attributes: {},
		});
		expect(asked).toEqual([]);
	});
});

describe("when users cannot look the subject up", () => {
	const unanswerable = (byHandle: Record<string, AuthContext | Entry>, asked: string[] = []) =>
		boot({
			users: [usersModule, unanswering],
			sessions: sessionsOf(byHandle, asked),
			registered: false,
		});

	it("answers the session's login attributes by users' names, vouched by users' source alone", async () => {
		const app = await unanswerable({
			u: context("s-alice", "users"),
			f: context("s-alice", loginSource.upstream("corp")),
		});
		const read = app.get(subjectAttributes);
		const attributes = { email: "alice@login.example", email_verified: true };
		expect(await read.of("s-alice", "u")).toEqual({ kind: "known", vouched: true, attributes });
		expect(await read.of("s-alice", "f")).toEqual({ kind: "known", vouched: false, attributes });
	});

	it("vouches for a login only under users' source, never an upstream's or another's", async () => {
		const app = await unanswerable({
			f: context("s-alice", loginSource.upstream("corp")),
			x: context("s-alice", "users:x"),
		});
		const read = app.get(subjectAttributes);
		for (const handle of ["f", "x"]) {
			const found = await read.of("s-alice", handle);
			expect(found, handle).toMatchObject({ kind: "known", vouched: false });
		}
	});

	it("reads the session at use", async () => {
		const asked: string[] = [];
		const app = await unanswerable({ u: context("s-alice", "users") }, asked);
		await app.get(subjectAttributes).of("s-alice", "u");
		expect(asked).toEqual(["u"]);
	});

	it("is unknown without a handle, for a session not entered (absent or short of a requirement), another subject's, or one with no attributes", async () => {
		const app = await unanswerable({
			short,
			other: context("s-bob", "users"),
			bare: context("s-alice"),
		});
		const read = app.get(subjectAttributes);
		for (const handle of [undefined, "closed", "short", "other", "bare"]) {
			expect(await read.of("s-alice", handle), String(handle)).toEqual({ kind: "unknown" });
		}
	});

	it("reads no session without a handle", async () => {
		const asked: string[] = [];
		const app = await unanswerable({ u: context("s-alice", "users") }, asked);
		expect(await app.get(subjectAttributes).of("s-alice")).toEqual({ kind: "unknown" });
		expect(asked).toEqual([]);
	});
});

describe("failures", () => {
	it("is unavailable when users is", async () => {
		const down = unavailableSwitch<Users>("users");
		const app = await boot({
			users: [switchedModule(usersModule, users, down)],
			sessions: sessionsOf({ h: context("s-alice", "users") }),
		});
		down.unavailable("bySubject");
		await expect(app.get(subjectAttributes).of("s-alice", "h")).rejects.toSatisfy(isUnavailable);
	});

	it("is unavailable when session is", async () => {
		const down = unavailableSwitch<Sessions>("session");
		const app = await boot({
			users: [usersModule, unanswering],
			sessions: switchedModule(sessionsOf({}), sessions, down),
			registered: false,
		});
		down.unavailable("entryOf");
		await expect(app.get(subjectAttributes).of("s-alice", "h")).rejects.toSatisfy(isUnavailable);
	});
});

describe("whether users vouches for a login's attributes", () => {
	it("vouches for a login that read users' ledger, never for an upstream's, whatever the IdP's name", () => {
		expect(vouches({ source: loginSource.users })).toBe(true);
		for (const source of [loginSource.upstream("users"), loginSource.upstream("google"), "other"]) {
			expect(vouches({ source }), source).toBe(false);
		}
	});
});

it("takes every handle its takes name", async () => {
	const modules = [
		memoryUsersStores().module,
		usersModule,
		secretHashModule,
		sessionsOf({}),
		reader,
	];
	const config = { ...kernelConfig(), ...usersConfig([]) };
	expect((await takesUnused({ modules, config }))["subject-attributes"]).toBeUndefined();
});
