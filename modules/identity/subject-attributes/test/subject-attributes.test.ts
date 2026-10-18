import { assemble, defineModule, isUnavailable, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, switchedModule, unavailableSwitch } from "@mod/kernel/testing";
import { loginSource } from "@mod/login-attributes";
import { type AuthContext, type Sessions, sessions } from "@mod/session";
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

/** Sessions by handle; `asked` lists each handle read. */
const sessionsOf = (byHandle: Record<string, AuthContext>, asked: string[] = []) =>
	defineModule({ name: "sessions" }, (m) => [
		m.provide(sessions).by(() =>
			stubSessions({
				openContext: async (handle) => {
					asked.push(handle);
					return byHandle[handle];
				},
			}),
		),
	]);

/** A ledger that cannot look users up by subject. */
const unanswering = defineModule({ name: "ledger" }, (m) => [
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
			source: "users",
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
			source: "users",
			vouched: true,
			attributes: {},
		});
		expect(asked).toEqual([]);
	});
});

describe("when users cannot look the subject up", () => {
	const unanswerable = (byHandle: Record<string, AuthContext>, asked: string[] = []) =>
		boot({
			users: [usersModule, unanswering],
			sessions: sessionsOf(byHandle, asked),
			registered: false,
		});

	it("answers the session's login attributes under the source it kept, by users' names", async () => {
		const app = await unanswerable({
			u: context("s-alice", "users"),
			f: context("s-alice", loginSource.upstream("corp")),
		});
		const read = app.get(subjectAttributes);
		expect(await read.of("s-alice", "u")).toEqual({
			kind: "known",
			source: "session:users",
			vouched: true,
			attributes: { email: "alice@login.example", email_verified: true },
		});
		expect(await read.of("s-alice", "f")).toMatchObject({ source: "session:upstream:corp" });
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

	it("is unknown without a handle, for a session not open, another subject's, or one with no attributes", async () => {
		const app = await unanswerable({
			other: context("s-bob", "users"),
			bare: context("s-alice"),
		});
		const read = app.get(subjectAttributes);
		for (const handle of [undefined, "closed", "other", "bare"]) {
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
		down.unavailable("openContext");
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
