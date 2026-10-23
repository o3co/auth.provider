import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { type Message, mail } from "@mod/mail";
import {
	type BindingProof,
	type BindingProofs,
	bindingProof,
	bindingProofs,
} from "@mod/mfa-binding-proof";
import { subjectAttributes } from "@mod/subject-attributes";
import { type Users, users } from "@mod/users";
import { beforeEach, expect, it } from "vitest";
import proofModule from "../src/module.ts";

let now = 1_800_000_000_000;
const logged = recordingLog();
const runtime = quietRuntime({ clock: { now: () => now }, log: logged.log });
/** What the account states, by subject; `null` cannot be told. */
const contacts = new Map<string, string | null>();
const sent: Message[] = [];
/** What each open session's login said of the user, by handle, and whether users vouches for it. */
const sessions = new Map<string, { email: string; vouched: boolean }>();
/** The contacts users was told were shown to be the subject's, in order. */
const verified: [string, unknown][] = [];
/** What the sender answers. */
let answer: "sent" | "limited" | "unavailable" = "sent";
/** Whether users keeps no more verified contacts for the subject, as past its limit. */
let contactsFull = false;
beforeEach(() => {
	now = 1_800_000_000_000;
	contacts.clear();
	sessions.clear();
	sent.length = 0;
	verified.length = 0;
	answer = "sent";
	contactsFull = false;
});

const seen = contract<BindingProof>("seen");
const outside = defineModule({ name: "outside" }, (m) => [
	m.provide(mail).by(() => ({
		send: async (message) => {
			if (answer === "unavailable") throw new Unavailable("mail");
			sent.push(message);
			return answer;
		},
	})),
	m.provide(users).by(
		() =>
			({
				claimedContacts: async (subject: string) => {
					const value = contacts.get(subject);
					if (value === null) return { kind: "unanswerable" };
					return value === undefined ? [] : [{ kind: "email", value }];
				},
				verifiedContact: async (subject: string, contact: unknown) => {
					if (contactsFull) throw new RangeError("users: a subject keeps at most 20 contacts");
					verified.push([subject, contact]);
				},
			}) satisfies Pick<Users, "claimedContacts" | "verifiedContact"> as never,
	),
	m.provide(subjectAttributes).by(() => ({
		of: async (_subject: string, handle?: string) => {
			const told = handle === undefined ? undefined : sessions.get(handle);
			if (!told) return { kind: "unknown" as const };
			return { kind: "known" as const, vouched: told.vouched, attributes: { email: told.email } };
		},
	})),
	m.provide(seen).by(async (c) => (await c.collect(bindingProofs))[0] as BindingProof),
]);

/** `mfa-binding-proof`, which hears this proof; only that it is there. */
const proofPlace = defineModule({ name: "binding-proof-place" }, (m) => [
	m.provide(bindingProof).by(() => ({}) as BindingProofs),
]);

const boot = async () =>
	(
		await assemble({
			modules: [outside, proofPlace, proofModule],
			config: kernelConfig(),
			runtime,
		})
	).get(seen);
const last = () => sent.at(-1) as Message;

it("refuses to boot without mfa-binding-proof composed, naming its contract, so the proof is never left unheard", async () => {
	await expect(
		assemble({ modules: [outside, proofModule], config: kernelConfig(), runtime }),
	).rejects.toSatisfy(
		(error) =>
			error instanceof BootRefused &&
			error.refusals.some(
				(r) => r.where === "mfa-email-proof" && r.reason.includes("mfa-binding-proof"),
			),
	);
});

it("proves the account's address before a first binding, by a long code good for ten minutes at most", async () => {
	const proof = await boot();
	expect(proof.name).toBe("account-email");
	contacts.set("ann", "ann@example.com");
	expect([await proof.available("ann"), await proof.available("bob")]).toEqual([true, false]);
	const asked = await proof.send("ann", now + 3_600_000);
	if (asked.kind !== "sent") throw new Error("not sent");
	expect(last()).toMatchObject({ purpose: "mfa-email.proof", values: { minutes: "10" } });
	const code = String(last().values.code);
	expect(await proof.check("ann", asked.kept, "0".repeat(16))).toBe(false);
	expect(verified).toEqual([]);
	expect(await proof.check("ann", asked.kept, code)).toBe(true);
	// The address the code went to is the subject's now: users keeps it as verified.
	expect(verified).toEqual([["ann", { kind: "email", value: "ann@example.com" }]]);
	now += 600_001;
	expect(await proof.check("ann", asked.kept, code)).toBe(false);
	expect(await proof.send("bob", now + 60_000)).toEqual({ kind: "refused" });
	// The caller's end, when it comes first; a limited sender keeps nothing.
	expect(await proof.send("ann", now + 30_000)).toMatchObject({ show: { expires_in: 30 } });
	expect(last().values.minutes).toBe("1");
	answer = "limited";
	expect(await proof.send("ann", now + 3_600_000)).toEqual({ kind: "limited" });
});

it("passes a right code though users keeps no more verified contacts, logging that it kept none and never the address", async () => {
	const proof = await boot();
	contacts.set("ann", "ann@example.com");
	const asked = await proof.send("ann", now + 3_600_000);
	if (asked.kind !== "sent") throw new Error("not sent");
	contactsFull = true;
	expect(await proof.check("ann", asked.kept, String(last().values.code))).toBe(true);
	expect(verified).toEqual([]);
	const warned = logged.lines().filter((l) => l.event === "mfa-email.contact_not_kept");
	expect(warned).toHaveLength(1);
	expect(JSON.stringify(warned)).not.toContain("ann@example.com");
});

it("passes a sender that cannot tell on as unavailable", async () => {
	const proof = await boot();
	contacts.set("ann", "ann@example.com");
	answer = "unavailable";
	await expect(proof.send("ann", now + 3_600_000)).rejects.toSatisfy(isUnavailable);
	expect(sent).toEqual([]);
});

it("fails as unavailable, judging no code, on a kept value it cannot read", async () => {
	const proof = await boot();
	await expect(proof.check("ann", "not a kept value", "x")).rejects.toSatisfy(isUnavailable);
	expect(verified).toEqual([]);
});

it("takes the address users stands behind: a session's or a held login's it vouches for, never an upstream's", async () => {
	const proof = await boot();
	contacts.set("lee", null);
	sessions.set("ledger", { email: "lee@example.com", vouched: true });
	sessions.set("upstream", { email: "lee@elsewhere.example", vouched: false });
	expect(await proof.available("lee", { kind: "session", handle: "ledger" })).toBe(true);
	expect(await proof.available("lee", { kind: "session", handle: "upstream" })).toBe(false);
	const vouched = { kind: "login" as const, email: "lee@example.com", vouched: true as const };
	expect(await proof.available("lee", vouched)).toBe(true);
	for (const from of [
		{ kind: "login" as const, email: "lee@example.com" },
		{ kind: "session" as const, handle: "h1" },
		undefined,
	]) {
		expect(await proof.available("lee", from), from?.kind).toBe(false);
		expect(await proof.send("lee", now + 60_000, from), from?.kind).toEqual({ kind: "refused" });
	}
	expect(sent).toEqual([]);
});

it("joins mfa-email, so it comes wherever a code by email is composed, and opts in alone", async () => {
	const { readFile } = await import("node:fs/promises");
	const manifest = JSON.parse(
		await readFile(new URL("../package.json", import.meta.url), "utf8"),
	) as { joins?: unknown; optIn?: unknown };
	expect([manifest.joins, manifest.optIn]).toEqual([["@mod/mfa-email"], true]);
});
