import { createHash, randomBytes } from "node:crypto";
import { isUnavailable } from "@mod/kernel";
import type { Credential } from "@mod/webauthn";
import {
	type CreationOptions,
	testCeremonies as ceremoniesFor,
	type RequestOptions,
	softwareAuthenticator,
	testOrigin,
} from "@mod/webauthn/testing";
import { expect, it } from "vitest";
import { keptChallenges } from "../src/challenges/challenges.ts";
import type { Requester } from "../src/contract.ts";
import { passkeysOver } from "../src/passkeys.ts";
import { keptPasskeys } from "../src/records.ts";
import type { StoredChallenge } from "../src/store.ts";
import { memoryStores, writeToken } from "./stores.ts";

/** The requester the tests ask and redeem as. */
const app = { by: "test", id: "app" };
const other = { by: "test", id: "other" };

const at = { origin: testOrigin };
const rp = { id: "rp.example", name: "RP", origins: [testOrigin], topOrigins: [], timeoutMs: 1000 };

/** Passkeys over memory stores, at a clock the test moves; `sam` holds one made by `authenticator`. */
async function kept(authenticator = softwareAuthenticator(), storeNow?: () => number) {
	let now = 1_000;
	const stores = memoryStores(storeNow ?? (() => now));
	const ceremonies = ceremoniesFor(
		rp,
		(n) => new Uint8Array(randomBytes(n)),
		() => now,
	);
	const records = keptPasskeys(stores.passkeys, writeToken);
	const challenges = keptChallenges(stores.challenges, () => now, 120_000);
	const passkeys = passkeysOver({ ceremonies, records, challenges, verification: "preferred" });
	const handle = await records.handleFor("sam", randomBytes(32).toString("base64url"));
	const { options, challenge } = ceremonies.creation({ handle, name: "sam" }, [], "preferred");
	const made = await ceremonies.attest(
		authenticator.create(options as CreationOptions, at),
		challenge,
		handle,
		"preferred",
	);
	const credential = (made as { credential: Credential }).credential;
	expect(await records.register("sam", credential, 10)).toBe("registered");
	/** An assertion answering a fresh challenge, made at the clock's time. */
	const answer = async (twist = {}) => {
		const { options } = await passkeys.challenge(app);
		now += 500;
		return authenticator.get(options as RequestOptions, at, twist);
	};
	const advance = (ms: number) => {
		now += ms;
	};
	return { stores, records, passkeys, ceremonies, credential, answer, authenticator, advance };
}

it("asks the same of everyone, and asserts the passkey's subject with when it was challenged", async () => {
	const { passkeys, answer, records, credential } = await kept();
	const { options } = await passkeys.challenge(app);
	expect(options).toMatchObject({ allowCredentials: [], rpId: "rp.example" });
	expect(await passkeys.assert(await answer(), app)).toEqual({
		kind: "asserted",
		subject: "sam",
		challengedAt: 1_000,
		userVerified: true,
		backupEligible: false,
	});
	expect((await records.passkey(credential.id))?.credential.signCount).toBe(1);
});

it("refuses an assertion with no user handle before it asks any store", async () => {
	const { passkeys, answer, stores } = await kept();
	const response = await answer({ userHandle: null });
	stores.down.challenges.unavailable("take", "open");
	stores.down.credentials.unavailable("read", "update");
	stores.down.subjects.unavailable("read");
	expect(await passkeys.assert(response, app)).toEqual({
		kind: "refused",
		reason: "no-user-handle",
	});
});

it("refuses a challenge past its end on kernel's clock, whatever the store's clock says", async () => {
	// The store's clock stands still: only kernel's time can end the challenge.
	const { passkeys, answer, advance } = await kept(softwareAuthenticator(), () => 1_000);
	const response = await answer();
	advance(120_000);
	expect(await passkeys.assert(response, app)).toMatchObject({
		kind: "refused",
		reason: "challenge",
	});
});

it("takes a challenge once", async () => {
	const { passkeys, answer } = await kept();
	const response = await answer();
	expect((await passkeys.assert(response, app)).kind).toBe("asserted");
	expect(await passkeys.assert(response, app)).toEqual({ kind: "refused", reason: "challenge" });
});

it("redeems a challenge made for a requester only for that requester, taking it either way", async () => {
	const { passkeys, authenticator } = await kept();
	const ask = async (requester: Requester) =>
		authenticator.get((await passkeys.challenge(requester)).options as RequestOptions, at);
	const made = await ask(app);
	expect(await passkeys.assert(made, other)).toEqual({ kind: "refused", reason: "challenge" });
	expect(await passkeys.assert(made, app)).toEqual({ kind: "refused", reason: "challenge" });
	expect((await passkeys.assert(await ask(app), app)).kind).toBe("asserted");
});

it("redeems a challenge made for a module's requester by that module's alone, whatever another module's id", async () => {
	const { passkeys, authenticator } = await kept();
	const client = { by: "webauthn-login", id: "C" };
	const browser = { by: "login-passkey", id: "C" };
	const ask = async (requester: { by: string; id: string }) =>
		authenticator.get((await passkeys.challenge(requester)).options as RequestOptions, at);
	// An assertion made for a client, redeemed by the browser login with that client's id as its mark.
	const forClient = await ask(client);
	expect(await passkeys.assert(forClient, browser)).toEqual({
		kind: "refused",
		reason: "challenge",
	});
	// The reverse: one made for a browser, redeemed by the token endpoint under the same id.
	const forBrowser = await ask(browser);
	expect(await passkeys.assert(forBrowser, client)).toEqual({
		kind: "refused",
		reason: "challenge",
	});
	expect((await passkeys.assert(await ask(client), client)).kind).toBe("asserted");
	// The two parts are kept apart, so no split of one string reads as another.
	const split = await ask({ by: "x", id: "y\u0000z" });
	expect(await passkeys.assert(split, { by: "x\u0000y", id: "z" })).toEqual({
		kind: "refused",
		reason: "challenge",
	});
});

it("throws, before the store is read, a requester whose part is no non-empty string", async () => {
	const { passkeys, answer } = await kept();
	const response = await answer();
	for (const requester of [
		{ by: "", id: "C" },
		{ by: "webauthn-login", id: "" },
		{ by: 1, id: "C" },
		{ id: "C" },
		null,
	]) {
		await expect(passkeys.challenge(requester as never), JSON.stringify(requester)).rejects.toThrow(
			TypeError,
		);
		await expect(
			passkeys.assert(response, requester as never),
			JSON.stringify(requester),
		).rejects.toThrow(TypeError);
	}
	// The challenge the answer was made for is still there: no throw took it.
	expect((await passkeys.assert(response, app)).kind).toBe("asserted");
});

it("takes and refuses an assertion challenge kept as format 1, though its digest is the id's, as it names no asker", async () => {
	const { passkeys, ceremonies, stores, authenticator } = await kept();
	const browser = { by: "login-passkey", id: "chosen" };
	const digestOf = (text: string) => createHash("sha256").update(text).digest("base64url");
	/** A format 1 assertion record kept for `requester`, and an answer to its challenge. */
	const opened = async (requester: string) => {
		const { options, challenge } = ceremonies.request([], "preferred");
		const before = { v: 1, kind: "assertion", requester, at: 1_000 };
		await stores.challenges.open(challenge, before as unknown as StoredChallenge, 120_000);
		return { challenge, response: authenticator.get(options as RequestOptions, at) };
	};
	// The one format 1 content that format 2's digest of the id matches: only the missing asker refuses it.
	const same = await opened(digestOf("chosen"));
	expect(await passkeys.assert(same.response, browser)).toEqual({
		kind: "refused",
		reason: "challenge",
	});
	// Taken: the same answer is refused again, its record the taken mark.
	expect(await passkeys.assert(same.response, browser)).toEqual({
		kind: "refused",
		reason: "challenge",
	});
	const left = await stores.challenges.take(same.challenge, {} as StoredChallenge);
	expect(left?.before).toMatchObject({ taken: true });
	// 0.18's digest of a raw client_id chosen to read as another module's requester, as Astra found it.
	const chosen = await opened(digestOf('["login-passkey","chosen"]'));
	expect(await passkeys.assert(chosen.response, browser)).toEqual({
		kind: "refused",
		reason: "challenge",
	});
});

it("redeems a format 2 assertion challenge for its own requester alone, another module's or another id refused", async () => {
	const { passkeys, authenticator } = await kept();
	const mine = { by: "webauthn-login", id: "C" };
	const ask = async () =>
		authenticator.get((await passkeys.challenge(mine)).options as RequestOptions, at);
	expect(await passkeys.assert(await ask(), { by: "login-passkey", id: "C" })).toEqual({
		kind: "refused",
		reason: "challenge",
	});
	expect(await passkeys.assert(await ask(), { by: "webauthn-login", id: "D" })).toEqual({
		kind: "refused",
		reason: "challenge",
	});
	expect((await passkeys.assert(await ask(), mine)).kind).toBe("asserted");
});

it("refuses a challenge kept for no requester, whoever redeems it", async () => {
	const { passkeys, ceremonies, stores, authenticator } = await kept();
	const { options, challenge } = ceremonies.request([], "preferred");
	const record = { v: 1, kind: "assertion", at: 1_000 } as unknown as StoredChallenge;
	await stores.challenges.open(challenge, record, 120_000);
	const response = authenticator.get(options as RequestOptions, at);
	expect(await passkeys.assert(response, app)).toEqual({ kind: "refused", reason: "challenge" });
});

it("keeps a digest of the requester, of one size whatever its length", async () => {
	const { passkeys, stores } = await kept();
	const { options } = await passkeys.challenge({ by: "test", id: "x".repeat(60_000) });
	const mark = {} as StoredChallenge;
	const taken = await stores.challenges.take((options as RequestOptions).challenge, mark);
	const record = JSON.stringify(taken?.before);
	expect(record.length).toBeLessThan(200);
	expect(record).not.toContain("xxxx");
});

it("refuses a credential it does not keep, and a handle that is not its holder's", async () => {
	const { passkeys, ceremonies, answer } = await kept();
	const stranger = softwareAuthenticator();
	const user = { handle: randomBytes(32).toString("base64url"), name: "kim" };
	stranger.create(ceremonies.creation(user, [], "preferred").options as CreationOptions, at);
	const { options } = await passkeys.challenge(app);
	const unknown = stranger.get(options as RequestOptions, at);
	expect(await passkeys.assert(unknown, app)).toEqual({
		kind: "refused",
		reason: "unknown-credential",
	});
	const other = randomBytes(32).toString("base64url");
	expect(await passkeys.assert(await answer({ userHandle: other }), app)).toEqual({
		kind: "refused",
		reason: "user-handle",
	});
});

it("refuses an assertion whose count another changed first", async () => {
	const { passkeys, answer, stores } = await kept();
	const response = await answer();
	stores.raceCredentials(
		(record) => ({ ...(record as object), signCount: 7 }) as unknown as typeof record,
	);
	expect(await passkeys.assert(response, app)).toEqual({ kind: "refused", reason: "raced" });
});

it("refuses an assertion whose passkey another subject took over meanwhile, its key and count the same, leaving the new record as it is", async () => {
	const { passkeys, answer, stores, records, credential } = await kept();
	const response = await answer();
	// Removed and registered again by another subject between the signature and the count.
	stores.raceCredentials(
		(record) => ({ ...(record as object), subject: "kim" }) as unknown as typeof record,
	);
	expect(await passkeys.assert(response, app)).toEqual({ kind: "refused", reason: "raced" });
	// The record that took the id over is not touched: its subject, key and count as written.
	expect(await records.passkey(credential.id)).toMatchObject({
		subject: "kim",
		credential: { publicKey: credential.publicKey, signCount: credential.signCount },
	});
});

it("refuses an assertion whose passkey was registered again by its subject with another key meanwhile, leaving that record as it is", async () => {
	const { passkeys, answer, stores, records, credential } = await kept();
	const response = await answer();
	// The same subject and id, the same count, another key: the passkey judged is gone.
	const other = randomBytes(65).toString("base64url");
	stores.raceCredentials(
		(record) => ({ ...(record as object), publicKey: other }) as unknown as typeof record,
	);
	expect(await passkeys.assert(response, app)).toEqual({ kind: "refused", reason: "raced" });
	expect(await records.passkey(credential.id)).toMatchObject({
		subject: "sam",
		credential: { publicKey: other, signCount: credential.signCount },
	});
});

it("answers unavailable when the store cannot tell, never a refusal", async () => {
	const { passkeys, answer, stores } = await kept();
	const response = await answer();
	stores.down.credentials.failNext("read");
	await expect(passkeys.assert(response, app)).rejects.toSatisfy(isUnavailable);
	stores.down.challenges.failNext("open");
	await expect(passkeys.challenge(app)).rejects.toSatisfy(isUnavailable);
});
