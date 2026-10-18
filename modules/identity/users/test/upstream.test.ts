import { assemble, BootRefused, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import {
	type Ledger,
	ledgers,
	type UpstreamNames,
	upstreamNames,
	users,
	type Verified,
} from "../src/contract.ts";
import usersModule from "../src/module.ts";
import { memoryUsersStores, testPasswordHash } from "../src/testing.ts";

const alice = { subject: "s-alice", attributes: { name: "Alice" } };
const none: Verified = { kind: "none" };
const device = { idp: "device", subject: "thumb-1" };

/** A ledger holding alice, by subject and, where `byUpstream` is given, by upstream identity. */
const ledgerOf = (byUpstream?: Ledger["byUpstream"]): Ledger => ({
	verify: async () => none,
	bySubject: async (subject) => (subject === alice.subject ? { kind: "user", user: alice } : none),
	...(byUpstream ? { byUpstream } : {}),
});
const answering = (answer: unknown) => ledgerOf(async () => answer as Verified);

const boot = async (
	ledger: Ledger,
	stores = memoryUsersStores(),
	names: readonly UpstreamNames[] = [],
) =>
	(
		await assemble({
			modules: [
				usersModule,
				stores.module,
				defineModule({ name: "test-ledger" }, (m) => [m.contribute(ledgers).by(() => ledger)]),
				...names.map((name, i) =>
					defineModule({ name: `names-${i}` }, (m) => [m.contribute(upstreamNames).by(() => name)]),
				),
			],
			config: { ...kernelConfig(), users: {} },
		})
	).get(users);

describe("a ledger that looks users up by upstream identity", () => {
	it("answers by the ledger alone: its user as given, its none over a link written here", async () => {
		const stores = memoryUsersStores();
		const before = await boot(ledgerOf(), stores);
		expect(await before.link("s-alice", device)).toBe("linked");
		expect((await before.byUpstream(device.idp, device.subject)).kind).toBe("user");
		const after = await boot(answering(none), stores);
		expect(await after.byUpstream(device.idp, device.subject)).toEqual(none);
		// Nor is that link removed here: it is not the ledger's, and stays as written.
		expect(await after.unlink("s-alice", device)).toBe("none");
		expect((await (await boot(ledgerOf(), stores)).byUpstream("device", "thumb-1")).kind).toBe(
			"user",
		);
		const found = await (await boot(answering({ kind: "user", user: alice }))).byUpstream("x", "y");
		expect(found).toEqual({ kind: "user", user: alice });
	});

	it("links nothing here: already where the ledger ties the identity to the subject, else conflict", async () => {
		const stores = memoryUsersStores();
		const tied = await boot(answering({ kind: "user", user: alice }), stores);
		expect(await tied.link("s-alice", device)).toBe("already");
		expect(await tied.link("s-bob", device)).toBe("conflict");
		expect(await tied.unlink("s-alice", device)).toBe("fixed");
		expect(await tied.unlink("s-bob", device)).toBe("none");
		const untied = await boot(answering(none), stores);
		expect(await untied.link("s-alice", device)).toBe("conflict");
		expect(await untied.unlink("s-alice", device)).toBe("none");
		// Nothing was written: a ledger without the upstream lookup finds no link.
		const plain = await boot(ledgerOf(), stores);
		expect(await plain.byUpstream(device.idp, device.subject)).toEqual(none);
	});

	it("is unavailable, never none, where the ledger fails or answers a malformed, empty or ill-formed subject", async () => {
		const failing = ledgerOf(async () => {
			throw new Error("down");
		});
		const answers: unknown[] = [
			{ kind: "user", user: { subject: "", attributes: {} } },
			{ kind: "user", user: { subject: "s-é", attributes: {} } },
			{ kind: "user", user: { subject: "s-alice" } },
			{ kind: "maybe" },
		];
		for (const ledger of [failing, ...answers.map(answering)]) {
			await expect((await boot(ledger)).byUpstream("device", "thumb-1")).rejects.toSatisfy(
				isUnavailable,
			);
		}
	});

	it("hands over a frozen copy, apart from what the ledger later does to its answer", async () => {
		const given = { kind: "user", user: { subject: "s-alice", attributes: { name: "Alice" } } };
		const found = await (await boot(answering(given))).byUpstream("device", "thumb-1");
		given.user.attributes.name = "Mallory";
		expect(found).toEqual({ kind: "user", user: alice });
		expect(Object.isFrozen(found.kind === "user" && found.user.attributes)).toBe(true);
	});
});

describe("IdP names declared to users", () => {
	const named = (name: string, issuer: string, declaredBy = "a"): UpstreamNames => ({
		declaredBy,
		names: [{ name, issuer }],
	});
	const google = "https://accounts.google.com";

	it("boots on one name for one issuer, also declared by two modules, and on a module declaring none", async () => {
		const names = [
			named("google", google, "federation"),
			named("google", google, "exchange"),
			{ declaredBy: "jwt-bearer", names: [] },
		];
		await expect(boot(ledgerOf(), memoryUsersStores(), names)).resolves.toBeDefined();
	});

	it("refuses a name declared for two issuers, naming it, the issuers and the modules", async () => {
		const twice = [
			named("google", google, "federation"),
			named("google", "https://evil.example", "x"),
		];
		const sameModule = [
			named("apple", "https://appleid.apple.com"),
			named("apple", "https://b.example"),
		];
		for (const names of [twice, sameModule]) {
			const refused = await boot(ledgerOf(), memoryUsersStores(), names).catch((e) => e);
			expect(refused).toBeInstanceOf(BootRefused);
			const told = (refused as BootRefused).refusals.map((r) => r.reason).join("; ");
			for (const d of names) {
				expect(told).toContain(d.declaredBy);
				for (const n of d.names) {
					expect(told).toContain(n.name);
					expect(told).toContain(n.issuer);
				}
			}
		}
	});

	it("refuses a registered user's upstream IdP no module declares, naming it at its key", async () => {
		const linked = (idp: string) => ({
			identifier: "alice",
			subject: "s-alice",
			"password-hash": testPasswordHash("p"),
			upstream: [
				{ idp: "google", subject: "g-1" },
				{ idp, subject: "u-1" },
			],
		});
		const registered = (idp: string, names: readonly UpstreamNames[]) =>
			assemble({
				modules: [
					usersModule,
					memoryUsersStores().module,
					...names.map((name, i) =>
						defineModule({ name: `names-${i}` }, (m) => [
							m.contribute(upstreamNames).by(() => name),
						]),
					),
				],
				config: { ...kernelConfig(), users: { registered: [linked(idp)] } },
			});
		const both = [
			named("google", google, "federation"),
			named("corp", "https://corp.example", "x"),
		];
		await expect(registered("corp", both)).resolves.toBeDefined();
		for (const names of [both.slice(0, 1), []]) {
			const refused = await registered("corp", names).catch((e) => e);
			expect(refused).toBeInstanceOf(BootRefused);
			const said = (refused as BootRefused).refusals;
			expect(said.map((r) => r.where)).toEqual(
				names.length === 0
					? ["users.registered.0.upstream.0.idp", "users.registered.0.upstream.1.idp"]
					: ["users.registered.0.upstream.1.idp"],
			);
			expect(said.at(-1)?.reason).toContain("corp");
		}
	});

	it("refuses an empty name or an empty issuer", async () => {
		for (const name of [named("", google), named("google", "")]) {
			await expect(boot(ledgerOf(), memoryUsersStores(), [name])).rejects.toBeInstanceOf(
				BootRefused,
			);
		}
	});
});
