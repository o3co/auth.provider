import { defineModule, isUnavailable, type Module } from "@mod/kernel";
import { quietRuntime, switchedModule, unavailableSwitch } from "@mod/kernel/testing";
import { type AuthContext, type Sessions, sessions } from "@mod/session";
import { ledgers, type UserAttributes, type Users, userAttribute, users } from "@mod/users";
import usersModule from "@mod/users/module";
import { testUser, usersConfig } from "@mod/users/testing";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { releasedClaims } from "../src/contract.ts";
import { booted, loginOf, published, sessionsOf, unanswering } from "./parts.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

/** oidc where users holds alice with `attributes`. */
const boot = (
	attributes: Record<string, unknown>,
	usersAs: Module = usersModule,
	byHandle: Record<string, AuthContext> = {},
) =>
	booted({
		runtime,
		config: usersConfig([testUser("alice", "pw", { subject: "s-alice", attributes })]),
		usersAs: [usersAs],
		sessionsAs: sessionsOf(byHandle),
	});

const released = async (attributes: Record<string, unknown>, scope: readonly string[]) =>
	(await boot(attributes)).get(releasedClaims).of("s-alice", scope);

/** As `released`, from a users that hands over its attributes unchecked, so oidc's own checks are what is seen. */
const unchecked = async (attributes: Record<string, unknown>, scope: readonly string[]) => {
	// Named users and taking any section, so it stands where users is configured.
	const standIn = defineModule({ name: "users", section: z.unknown() }, (m) => [
		m.provide(users).by(
			() =>
				({
					bySubject: async (subject: string) => ({ kind: "user", user: { subject, attributes } }),
				}) as unknown as Users,
		),
	]);
	return (await boot({}, standIn)).get(releasedClaims).of("s-alice", scope);
};

const full = {
	[userAttribute.name]: "Alice",
	[userAttribute.picture]: "https://pic.example/a",
	[userAttribute.email]: "alice@example.com",
	[userAttribute.emailVerified]: true,
	[userAttribute.groups]: ["admins", "staff"],
} satisfies UserAttributes;

describe("the claim table", () => {
	it("releases name and picture for profile", async () => {
		expect(await released(full, ["profile"])).toEqual({
			name: "Alice",
			picture: "https://pic.example/a",
		});
	});

	it("releases email and email_verified for email", async () => {
		expect(await released(full, ["email"])).toEqual({
			email: "alice@example.com",
			email_verified: true,
		});
	});

	it("reads email_verified from users' attribute of that name alone", async () => {
		const verified = { [userAttribute.emailVerified]: true };
		expect(await released(verified, ["email"])).toEqual({ email_verified: true });
		expect(await released({ emailVerified: true }, ["email"])).toEqual({});
	});

	it("releases groups for groups", async () => {
		expect(await released(full, ["groups"])).toEqual({ groups: ["admins", "staff"] });
	});

	it("releases nothing for openid alone, and never sub", async () => {
		expect(await released(full, ["openid"])).toEqual({});
		expect(await released({ ...full, sub: "other" }, ["openid", "profile"])).not.toHaveProperty(
			"sub",
		);
	});

	it("leaves out a value of another type, a nested object, and non-string groups", async () => {
		const odd = {
			[userAttribute.name]: { first: "Alice" },
			[userAttribute.picture]: 7,
			[userAttribute.email]: ["alice@example.com"],
			[userAttribute.emailVerified]: "true",
			[userAttribute.groups]: ["admins", 1, { name: "x" }, ["y"], null],
		};
		expect(await unchecked(odd, ["profile", "email", "groups"])).toStrictEqual({
			groups: ["admins"],
		});
		expect(await unchecked({ groups: { admins: true } }, ["groups"])).toEqual({});
	});

	it("never releases an attribute outside the table, under any scope", async () => {
		const extra = { ...full, role: "root", hd: "example.com", phone: "+1", address: "x" };
		const answer = await released(extra, ["openid", "profile", "email", "groups", "phone"]);
		expect(Object.keys(answer).sort()).toEqual([
			"email",
			"email_verified",
			"groups",
			"name",
			"picture",
		]);
	});

	it("lists in claims_supported every claim it releases", async () => {
		const app = await boot(full);
		const all = await app.get(releasedClaims).of("s-alice", ["profile", "email", "groups"]);
		const supported = app.get(published).find((item) => item.name === "claims_supported");
		expect(Object.keys(all)).toHaveLength(5);
		expect(supported?.value).toEqual(expect.arrayContaining(Object.keys(all)));
	});

	it("counts only whole scope words, so a word joined by a tab or other blank releases nothing", async () => {
		expect(await released(full, ["profile\temail", "groups\n", " email", "PROFILE"])).toEqual({});
	});
});

describe("released claims", () => {
	it("answers nothing for a subject with no user", async () => {
		const app = await boot(full);
		expect(await app.get(releasedClaims).of("s-nobody", ["profile", "email"])).toEqual({});
	});

	it("reads the attributes from users on each request", async () => {
		let name = "Alice";
		const ledger = defineModule({ name: "ledger" }, (m) => [
			m.contribute(ledgers).by(() => ({
				verify: async () => ({ kind: "none" }),
				bySubject: async (subject) => ({
					kind: "user",
					user: { subject, attributes: { [userAttribute.name]: name } },
				}),
			})),
		]);
		const app = await booted({ runtime, usersAs: [usersModule, ledger] });
		expect(await app.get(releasedClaims).of("s-alice", ["profile"])).toEqual({ name: "Alice" });
		name = "Alicia";
		expect(await app.get(releasedClaims).of("s-alice", ["profile"])).toEqual({ name: "Alicia" });
	});

	it("is unavailable when users is, never an empty answer", async () => {
		const down = unavailableSwitch<Users>("users");
		const app = await boot(full, switchedModule(usersModule, users, down));
		down.unavailable("bySubject");
		await expect(app.get(releasedClaims).of("s-alice", ["profile"])).rejects.toSatisfy(
			isUnavailable,
		);
	});

	it("reads users alone when users answers for the subject, never the session's login", async () => {
		const app = await boot({ [userAttribute.name]: "Alice" }, usersModule, {
			h: loginOf("s-alice", "users"),
		});
		expect(await app.get(releasedClaims).of("s-alice", ["profile", "email"], "h")).toEqual({
			name: "Alice",
		});
	});
});

describe("released claims where users cannot look the subject up", () => {
	const byHandle = {
		u: loginOf("s-alice", "users"),
		f: loginOf("s-alice", "federation:corp"),
		other: loginOf("s-bob", "users"),
	};
	const unanswerable = (sessionsAs: Module = sessionsOf(byHandle)) =>
		booted({ runtime, usersAs: [usersModule, unanswering], sessionsAs });
	const scope = ["openid", "profile", "email"];

	it("releases the session's login attributes through the table when users stated them", async () => {
		const claims = (await unanswerable()).get(releasedClaims);
		const fromLogin = { email: "alice@login.example", email_verified: true, name: "Al" };
		expect(await claims.of("s-alice", scope, "u")).toEqual(fromLogin);
		expect(await claims.of("s-alice", ["profile"], "u")).toEqual({ name: "Al" });
	});

	it("never releases an upstream's word that the email is verified, only its email and profile", async () => {
		const claims = (await unanswerable()).get(releasedClaims);
		expect(await claims.of("s-alice", scope, "f")).toEqual({
			email: "alice@login.example",
			name: "Al",
		});
	});

	it("releases no claims without an open session of the subject's that holds attributes", async () => {
		const claims = (await unanswerable()).get(releasedClaims);
		for (const handle of [undefined, "closed", "other"]) {
			expect(await claims.of("s-alice", scope, handle), String(handle)).toEqual({});
		}
	});

	it("is unavailable when session is, never an empty answer", async () => {
		const down = unavailableSwitch<Sessions>("session");
		const app = await unanswerable(switchedModule(sessionsOf(byHandle), sessions, down));
		down.unavailable("entryOf", "openContext");
		await expect(app.get(releasedClaims).of("s-alice", scope, "u")).rejects.toSatisfy(
			isUnavailable,
		);
	});
});
