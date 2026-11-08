import {
	assemble,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { type Message, mail } from "@mod/mail";
import { subjectAttributes } from "@mod/subject-attributes";
import { type Users, users } from "@mod/users";
import { beforeEach, expect, it } from "vitest";
import {
	longCode,
	type MailedCodes,
	mailedCodes,
	mailedCodesIn,
	mailedTakes,
	readLongCode,
	readShortCode,
	shortCode,
} from "../src/contract.ts";

let now = 1_800_000_000_000;
/** What the account states, by subject; `null` cannot be told. */
const contacts = new Map<string, string | null>();
const sent: Message[] = [];
/** What each open session's login said of the user, by handle, and whether users vouches for it. */
const sessions = new Map<string, { email: string; vouched: boolean }>();
/** What the sender answers; `unavailable` throws as a sender that cannot tell. */
let answer: "sent" | "limited" | "unavailable" = "sent";
beforeEach(() => {
	now = 1_800_000_000_000;
	contacts.clear();
	sessions.clear();
	sent.length = 0;
	answer = "sent";
});

const parts = {
	mail: {
		send: async (message: Message) => {
			if (answer === "unavailable") throw new Unavailable("mail");
			sent.push(message);
			return answer;
		},
	},
	users: {
		claimedContacts: async (subject: string) => {
			const value = contacts.get(subject);
			if (value === null) return { kind: "unanswerable" };
			return value === undefined ? [] : [{ kind: "email", value }];
		},
	} satisfies Pick<Users, "claimedContacts"> as never,
	attributes: () => ({
		of: async (_subject: string, handle?: string) => {
			const told = handle === undefined ? undefined : sessions.get(handle);
			if (!told) return { kind: "unknown" as const };
			return { kind: "known" as const, vouched: told.vouched, attributes: { email: told.email } };
		},
	}),
	now: () => now,
};
const mailed: MailedCodes = mailedCodes(parts);
const last = () => sent.at(-1) as Message;

it("takes the account's address in one form: NFC, its domain in ASCII and lower case", async () => {
	contacts.set("ann", "Ann@BüCHER.example");
	expect(await mailed.addressNow("ann")).toBe("Ann@xn--bcher-kva.example");
	contacts.set("amy", "Amélie@example.com");
	expect(await mailed.addressNow("amy")).toBe("Amélie@example.com");
});

it("gives no address for an account without one, one mail does not take, or a users that cannot tell", async () => {
	contacts.set("cal", "not an address");
	contacts.set("dee", null);
	for (const subject of ["bob", "cal", "dee"]) {
		expect(await mailed.addressNow(subject), subject).toBeUndefined();
	}
});

it("takes the address of a session or a held login users vouches for, never an upstream's", async () => {
	contacts.set("lee", null);
	sessions.set("ledger", { email: "Lee@EXAMPLE.com", vouched: true });
	sessions.set("upstream", { email: "lee@elsewhere.example", vouched: false });
	const at = (from: Parameters<MailedCodes["addressNow"]>[1]) => mailed.addressNow("lee", from);
	expect(await at({ kind: "session", handle: "ledger" })).toBe("Lee@example.com");
	expect(await at({ kind: "login", email: "lee@example.com", vouched: true })).toBe(
		"lee@example.com",
	);
	for (const from of [
		{ kind: "session" as const, handle: "upstream" },
		{ kind: "session" as const, handle: "unknown" },
		{ kind: "login" as const, email: "lee@example.com" },
		undefined,
	]) {
		expect(await at(from), JSON.stringify(from)).toBeUndefined();
	}
});

it("prefers the address the account states to a login's", async () => {
	contacts.set("ann", "ann@example.com");
	const login = { kind: "login" as const, email: "ann@elsewhere.example", vouched: true as const };
	expect(await mailed.addressNow("ann", login)).toBe("ann@example.com");
});

it("mails the code under the caller's purpose, showing the address masked and the seconds left", async () => {
	const until = now + 90_000;
	const answered = await mailed.send("caller.purpose", "Ann@example.com", "C0DE", until);
	expect(last()).toEqual({
		purpose: "caller.purpose",
		to: "Ann@example.com",
		values: { code: "C0DE", minutes: "2" },
		expiresAt: until,
	});
	expect(answered).toEqual({
		kind: "sent",
		show: { sent_to: "A***@example.com", expires_in: 90 },
		kept: JSON.stringify({ code: "C0DE", until }),
	});
});

it("masks an address by its first character, however many code units it takes", async () => {
	const answered = await mailed.send("p", "\u{20bb7}田@example.jp", "C0DE", now + 60_000);
	expect(answered).toMatchObject({ show: { sent_to: "\u{20bb7}***@example.jp" } });
});

it("is limited at the sender's limit, and passes a sender that cannot tell on as unavailable", async () => {
	answer = "limited";
	expect(await mailed.send("p", "ann@example.com", "C0DE", now + 60_000)).toEqual({
		kind: "limited",
	});
	answer = "unavailable";
	await expect(mailed.send("p", "ann@example.com", "C0DE", now + 60_000)).rejects.toSatisfy(
		isUnavailable,
	);
});

it("matches the kept code until its end, and nothing missing", () => {
	const kept = { code: "123456", until: now + 60_000 };
	expect(mailed.matches(kept, "123456")).toBe(true);
	expect(mailed.matches(kept, "123457")).toBe(false);
	expect(mailed.matches(kept, undefined)).toBe(false);
	expect(mailed.matches(undefined, "123456")).toBe(false);
	now += 60_000;
	expect(mailed.matches(kept, "123456")).toBe(true);
	now += 1;
	expect(mailed.matches(kept, "123456")).toBe(false);
});

it("makes a long code of 16 characters of Crockford's base32 from 10 random bytes", () => {
	const asked: number[] = [];
	const code = longCode((n) => {
		asked.push(n);
		return new Uint8Array(n).fill(255);
	});
	expect([asked, code]).toEqual([[10], "Z".repeat(16)]);
	expect(longCode((n) => new Uint8Array(n))).toBe("0".repeat(16));
});

it("reads a long code in any case, with hyphens or spaces, O as 0 and I or L as 1", () => {
	expect(readLongCode(" abcd-efgh ijkl mnop ")).toBe("ABCDEFGH1JK1MN0P");
	expect(readLongCode("ABCDEFGH1JK1MN0")).toBeUndefined();
	expect(readLongCode("ABCDEFGH1JK1MN0U")).toBeUndefined();
	expect(readLongCode("x".repeat(65))).toBeUndefined();
});

it("reads only ASCII letters, digits, hyphens and spaces, never a character that changes case into one", () => {
	for (const typed of [
		"ıBCDEFGH1JK1MN0P",
		"ABCDEFGH1JK1MN0ſ",
		"ﬀBCDEFGH1JK1MN0",
		"ABCDEFGH　1JK1MN0P",
		"ABCDEFGH\t1JK1MN0P",
	]) {
		expect(readLongCode(typed), JSON.stringify(typed)).toBeUndefined();
	}
});

it("draws six digits evenly: a draw past the last whole million is drawn again", () => {
	const draws = [
		[255, 255, 255, 255],
		[0, 0, 0, 1],
	];
	expect(shortCode(() => Uint8Array.from(draws.shift() ?? []))).toBe("000001");
});

it("reads six digits with white space around them only", () => {
	expect(readShortCode(" 012345 ")).toBe("012345");
	expect(readShortCode("　012345\n")).toBe("012345");
	for (const typed of ["012 345", "01234", "0123456", "01234x", " ".repeat(60) + "012345"]) {
		expect(readShortCode(typed), JSON.stringify(typed)).toBeUndefined();
	}
});

const seen = contract<MailedCodes>("seen");
const caller = defineModule({ name: "caller", replicaSafe: true, takes: mailedTakes }, (m) => [
	m.provide(seen).by((c) => mailedCodesIn(c)),
]);
const given = defineModule({ name: "given", replicaSafe: false, takes: [] }, (m) => [
	m.provide(mail).by(() => parts.mail),
	m.provide(users).by(() => parts.users),
	m.provide(subjectAttributes).by(() => parts.attributes()),
]);
const composition = () => ({
	modules: [given, caller],
	config: kernelConfig(),
	runtime: quietRuntime({ clock: { now: () => now } }),
});

it("takes the same from the assembly, a caller naming mailedTakes taking all it names", async () => {
	const app = await assemble(composition());
	contacts.set("ann", "ann@example.com");
	const from = app.get(seen);
	expect(await from.addressNow("ann")).toBe("ann@example.com");
	expect((await from.send("p", "ann@example.com", "C0DE", now + 60_000)).kind).toBe("sent");
	expect((await takesUnused(composition())).caller).toBeUndefined();
});
