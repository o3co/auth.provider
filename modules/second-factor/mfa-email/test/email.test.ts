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
import { type Message, mail, mailPurposes, mailTemplates } from "@mod/mail";
import {
	type BindingProof,
	type BindingProofs,
	bindingProof,
	bindingProofs,
} from "@mod/mfa-binding-proof";
import { type FactorKind, factorKinds } from "@mod/mfa-extensions";
import { subjectAttributes } from "@mod/subject-attributes";
import { type Users, users } from "@mod/users";
import { beforeEach, expect, it } from "vitest";
import { readLongCode, shortCode } from "../src/codes.ts";
import emailModule from "../src/module.ts";

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
/** What the sender answers; `unavailable` throws as a sender that cannot tell. */
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

const seen = contract<{
	kind: FactorKind;
	proof: BindingProof;
	purposes: readonly string[];
	templates: readonly string[];
}>("seen");
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
			return {
				kind: "known" as const,
				vouched: told.vouched,
				attributes: { email: told.email },
			};
		},
	})),
	m.provide(seen).by(async (c) => ({
		kind: (await c.collect(factorKinds))[0] as FactorKind,
		proof: (await c.collect(bindingProofs))[0] as BindingProof,
		purposes: (await c.collect(mailPurposes)).map((p) => p.purpose),
		templates: (await c.collect(mailTemplates)).map((t) => t.purpose),
	})),
]);

/** `mfa-binding-proof`, which this kind's proof needs composed; only that it is there. */
const proofPlace = defineModule({ name: "binding-proof-place" }, (m) => [
	m.provide(bindingProof).by(() => ({}) as BindingProofs),
]);

async function boot(settings: Record<string, unknown> = {}) {
	const app = await assemble({
		modules: [outside, proofPlace, emailModule],
		config: { ...kernelConfig(), "mfa-email": settings },
		runtime,
	});
	return app.get(seen);
}
const last = () => sent.at(-1) as Message;

/** Ann's account states `address`, and her factor is enrolled at it. */
async function annEnrolled(address = "ann@example.com", settings: Record<string, unknown> = {}) {
	const { kind } = await boot(settings);
	contacts.set("ann", address);
	const enrolled = await kind.enroll("ann", []);
	if (!("secret" in enrolled)) throw new Error("not enrolled");
	return { kind, enrolled, factor: { secret: enrolled.secret, state: {} } };
}

it("refuses to boot without mfa-binding-proof composed, naming its contract, so its proof is never left unheard", async () => {
	await expect(
		assemble({ modules: [outside, emailModule], config: kernelConfig(), runtime }),
	).rejects.toSatisfy(
		(error) =>
			error instanceof BootRefused &&
			error.refusals.some((r) => r.where === "mfa-email" && r.reason.includes("mfa-binding-proof")),
	);
});

it("declares a guessable factor of amr email, adding mfa and counting only when told", async () => {
	expect((await boot()).kind).toMatchObject({
		kind: "email",
		amr: ["email"],
		addsSecondFactor: false,
		guessable: true,
		counts: false,
	});
	expect((await boot({ "adds-second-factor": true })).kind).toMatchObject({
		addsSecondFactor: true,
		counts: true,
	});
});

it("binds the account's address by a long code sent there, showing the address masked", async () => {
	const { kind, enrolled } = await annEnrolled("Ann@Example.COM");
	expect(enrolled.show).toEqual({ sent_to: "A***@example.com", expires_in: 600 });
	expect(last()).toMatchObject({ purpose: "mfa-email.enrollment", to: "Ann@example.com" });
	const code = String(last().values.code);
	expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{16}$/);
	const typed = `${code.slice(0, 8).toLowerCase()}-${code.slice(8)}`;
	expect(await kind.verify(enrolled.secret, null, typed)).toEqual({ kind: "valid", state: {} });
	expect(await kind.verify(enrolled.secret, null, "0".repeat(16))).toEqual({ kind: "invalid" });
	now += 600_001;
	expect(await kind.verify(enrolled.secret, null, code)).toEqual({ kind: "invalid" });
});

it("lets a code live as long as code-lifetime says", async () => {
	const { kind, enrolled } = await annEnrolled("ann@example.com", { "code-lifetime": "5m" });
	expect(enrolled.show).toMatchObject({ expires_in: 300 });
	const code = String(last().values.code);
	now += 300_001;
	expect(await kind.verify(enrolled.secret, null, code)).toEqual({ kind: "invalid" });
});

it("takes one mailbox in one form, its domain in ASCII and lower case", async () => {
	const { kind, enrolled, factor } = await annEnrolled("ann@B\u00fcCHER.example");
	expect(enrolled.show).toMatchObject({ sent_to: "a***@xn--bcher-kva.example" });
	expect(last()).toMatchObject({ to: "ann@xn--bcher-kva.example" });
	expect(await kind.enroll("ann", [factor])).toEqual({ kind: "duplicate" });
	contacts.set("ann", "ann@XN--BCHER-KVA.example");
	expect((await kind.challenge?.("ann", factor, now + 60_000))?.kind).toBe("sent");
});

it("masks an address by its first character, however many code units it takes", async () => {
	const { enrolled } = await annEnrolled("\u{20bb7}\u7530@example.jp");
	expect(enrolled.show).toMatchObject({ sent_to: "\u{20bb7}***@example.jp" });
});

it("refuses before sending an address the subject already holds, and an account without one", async () => {
	const { kind, factor } = await annEnrolled();
	sent.length = 0;
	expect(await kind.enroll("ann", [factor])).toEqual({ kind: "duplicate" });
	expect(await kind.enroll("bob", [])).toEqual({ kind: "refused" });
	contacts.set("cal", "not an address");
	expect(await kind.enroll("cal", [])).toEqual({ kind: "refused" });
	expect(sent).toEqual([]);
});

it("refuses while users cannot tell, and is limited at the sender's limit", async () => {
	const { kind } = await boot();
	contacts.set("dee", null);
	expect(await kind.enroll("dee", [])).toEqual({ kind: "refused" });
	contacts.set("ann", "ann@example.com");
	answer = "limited";
	expect(await kind.enroll("ann", [])).toEqual({ kind: "limited" });
});

it("passes a sender that cannot tell on as unavailable, whatever it was sending", async () => {
	const { kind, factor } = await annEnrolled();
	const { proof } = await boot();
	sent.length = 0;
	answer = "unavailable";
	await expect(kind.enroll("ann", [])).rejects.toSatisfy(isUnavailable);
	await expect(kind.challenge?.("ann", factor, now + 120_000)).rejects.toSatisfy(isUnavailable);
	await expect(proof.send("ann", now + 3_600_000)).rejects.toSatisfy(isUnavailable);
	expect(sent).toEqual([]);
});

it("sends six digits to the factor's address, good until the transaction's end when that comes first", async () => {
	const { kind, factor } = await annEnrolled();
	const challenged = await kind.challenge?.("ann", factor, now + 120_000);
	if (challenged?.kind !== "sent") throw new Error("not sent");
	expect(challenged.show).toEqual({ sent_to: "a***@example.com", expires_in: 120 });
	expect(last()).toMatchObject({ purpose: "mfa-email.login", values: { minutes: "2" } });
	const code = String(last().values.code);
	expect(code).toMatch(/^[0-9]{6}$/);
	expect(await kind.verify(factor.secret, factor.state, ` ${code} `, challenged.kept)).toEqual({
		kind: "valid",
		state: {},
	});
	expect((await kind.verify(factor.secret, factor.state, "000000x", challenged.kept)).kind).toBe(
		"invalid",
	);
	const wrong = code === "000000" ? "000001" : "000000";
	expect((await kind.verify(factor.secret, factor.state, wrong, challenged.kept)).kind).toBe(
		"invalid",
	);
	expect((await kind.verify(factor.secret, factor.state, code)).kind).toBe("invalid");
	now += 120_001;
	expect((await kind.verify(factor.secret, factor.state, code, challenged.kept)).kind).toBe(
		"invalid",
	);
});

it("sends nothing to an address the account no longer states, telling the contact changed", async () => {
	const { kind, factor } = await annEnrolled();
	sent.length = 0;
	const changed = { kind: "refused", reason: "contact-changed" };
	contacts.set("ann", "ann@elsewhere.example");
	expect(await kind.challenge?.("ann", factor, now + 60_000)).toEqual(changed);
	contacts.delete("ann");
	expect(await kind.challenge?.("ann", factor, now + 60_000)).toEqual(changed);
	expect(sent).toEqual([]);
});

it("takes the address of a user users cannot tell from a session whose login users vouches for, never an upstream's", async () => {
	const { kind, proof } = await boot();
	contacts.set("lee", null);
	sessions.set("ledger", { email: "lee@example.com", vouched: true });
	sessions.set("upstream", { email: "lee@elsewhere.example", vouched: false });
	const fromLedger = { kind: "session" as const, handle: "ledger" };
	const fromUpstream = { kind: "session" as const, handle: "upstream" };
	expect(await proof.available("lee", fromLedger)).toBe(true);
	expect(await proof.available("lee", fromUpstream)).toBe(false);
	expect(await kind.enroll("lee", [], fromUpstream)).toEqual({ kind: "refused" });
	const enrolled = await kind.enroll("lee", [], fromLedger);
	if (!("secret" in enrolled)) throw new Error("not enrolled");
	expect(last().to).toBe("lee@example.com");
	const factor = { secret: enrolled.secret, state: {} };
	expect((await kind.challenge?.("lee", factor, now + 60_000, fromLedger))?.kind).toBe("sent");
	// The session's address changed: the factor's is no longer the one users stands behind.
	sessions.set("ledger", { email: "lee@moved.example", vouched: true });
	expect(await kind.challenge?.("lee", factor, now + 60_000, fromLedger)).toEqual({
		kind: "refused",
		reason: "contact-changed",
	});
});

it("takes the address of a held login users vouches for, never an upstream login's", async () => {
	const { kind, proof } = await boot();
	contacts.set("lee", null);
	const vouched = { kind: "login" as const, email: "lee@example.com", vouched: true as const };
	const upstream = { kind: "login" as const, email: "lee@elsewhere.example" };
	expect(await proof.available("lee", vouched)).toBe(true);
	expect(await proof.available("lee", upstream)).toBe(false);
	expect(await kind.enroll("lee", [], upstream)).toEqual({ kind: "refused" });
	const enrolled = await kind.enroll("lee", [], vouched);
	if (!("secret" in enrolled)) throw new Error("not enrolled");
	expect(last().to).toBe("lee@example.com");
	const factor = { secret: enrolled.secret, state: {} };
	expect((await kind.challenge?.("lee", factor, now + 60_000, vouched))?.kind).toBe("sent");
	expect(
		await kind.challenge?.("lee", factor, now + 60_000, { ...vouched, email: "lee@moved.example" }),
	).toEqual({ kind: "refused", reason: "contact-changed" });
});

it("never takes an address from a login, or from a session users does not stand behind", async () => {
	const { kind, proof } = await boot();
	contacts.set("lee", null);
	const login = { kind: "login" as const, email: "lee@example.com" };
	const session = { kind: "session" as const, handle: "h1" };
	for (const from of [login, session, undefined]) {
		const name = from?.kind ?? "nothing";
		expect(await proof.available("lee", from), name).toBe(false);
		expect(await proof.send("lee", now + 60_000, from), name).toEqual({ kind: "refused" });
		expect(await kind.enroll("lee", [], from), name).toEqual({ kind: "refused" });
	}
	expect(sent).toEqual([]);
	// A factor bound at the login's address before is never sent to again.
	const { enrolled } = await annEnrolled("lee@example.com");
	sent.length = 0;
	const factor = { secret: enrolled.secret, state: {} };
	const changed = { kind: "refused", reason: "contact-changed" };
	for (const from of [login, session, undefined]) {
		expect(await kind.challenge?.("lee", factor, now + 60_000, from), from?.kind).toEqual(changed);
	}
	expect(sent).toEqual([]);
});

it("fails as unavailable, sending nothing and judging no code, on a stored value it cannot read", async () => {
	const { kind, factor } = await annEnrolled();
	const unreadable = "not a stored value";
	sent.length = 0;
	const broken = { ...factor, secret: unreadable };
	await expect(kind.challenge?.("ann", broken, now + 60_000)).rejects.toSatisfy(isUnavailable);
	expect(sent).toEqual([]);
	await expect(kind.verify(unreadable, null, "x", undefined)).rejects.toSatisfy(isUnavailable);
	await expect(kind.verify(factor.secret, factor.state, "123456", unreadable)).rejects.toSatisfy(
		isUnavailable,
	);
	await expect(kind.enroll("ann", [broken])).rejects.toSatisfy(isUnavailable);
	const { proof } = await boot();
	await expect(proof.check("ann", unreadable, "x")).rejects.toSatisfy(isUnavailable);
});

it("passes a right code though users keeps no more verified contacts, logging that it kept none and never the address", async () => {
	const { proof } = await boot();
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

it("proves the account's address before a first binding, by a long code good for ten minutes at most", async () => {
	const { proof } = await boot();
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
	// A mail never says a code lives no minutes, even at its very end.
	await proof.send("ann", now);
	expect(last().values.minutes).toBe("1");
	answer = "limited";
	expect(await proof.send("ann", now + 3_600_000)).toEqual({ kind: "limited" });
});

it("sends to an address in NFC, however the account states it", async () => {
	const { kind } = await boot();
	contacts.set("amy", "Ame\u0301lie@example.com");
	expect("secret" in (await kind.enroll("amy", []))).toBe(true);
	expect(last().to).toBe("Am\u00e9lie@example.com");
});

it("draws six digits evenly: a draw past the last whole million is drawn again", () => {
	const draws = [
		[255, 255, 255, 255],
		[0, 0, 0, 1],
	];
	expect(shortCode(() => Uint8Array.from(draws.shift() ?? []))).toBe("000001");
});

it("declares each purpose it sends, and words none: its wording module does", async () => {
	const { purposes, templates } = await boot();
	expect([...purposes].sort()).toEqual([
		"mfa-email.enrollment",
		"mfa-email.login",
		"mfa-email.proof",
	]);
	expect(templates).toEqual([]);
});

it("reads a long code in any case, with hyphens or spaces, O as 0 and I or L as 1", () => {
	expect(readLongCode(" abcd-efgh ijkl mnop ")).toBe("ABCDEFGH1JK1MN0P");
	expect(readLongCode("ABCDEFGH1JK1MN0")).toBeUndefined();
	expect(readLongCode("ABCDEFGH1JK1MN0U")).toBeUndefined();
	expect(readLongCode("x".repeat(65))).toBeUndefined();
});

it("reads only ASCII letters, digits, hyphens and spaces, never a character that changes case into one", () => {
	for (const typed of [
		"\u0131BCDEFGH1JK1MN0P",
		"ABCDEFGH1JK1MN0\u017f",
		"\ufb00BCDEFGH1JK1MN0",
		"ABCDEFGH\u30001JK1MN0P",
		"ABCDEFGH\t1JK1MN0P",
	]) {
		expect(readLongCode(typed), JSON.stringify(typed)).toBeUndefined();
	}
});
