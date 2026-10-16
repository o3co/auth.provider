import { randomBytes } from "node:crypto";
import { isUnavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import { ceremoniesFor } from "../src/ceremony/ceremony.ts";
import type { Credential } from "../src/contract.ts";
import { passkeysOver } from "../src/passkeys.ts";
import { keptChallenges, keptPasskeys } from "../src/records.ts";
import type { StoredChallenge } from "../src/store.ts";
import {
	type CreationOptions,
	type RequestOptions,
	softwareAuthenticator,
	testOrigin,
} from "../src/testing.ts";
import { memoryStores } from "./stores.ts";

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
	const records = keptPasskeys(stores.passkeys);
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
		const { options } = await passkeys.challenge("app");
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
	const { options } = await passkeys.challenge("app");
	expect(options).toMatchObject({ allowCredentials: [], rpId: "rp.example" });
	expect(await passkeys.assert(await answer(), "app")).toEqual({
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
	expect(await passkeys.assert(response, "app")).toEqual({
		kind: "refused",
		reason: "no-user-handle",
	});
});

it("refuses a challenge past its end on kernel's clock, whatever the store's clock says", async () => {
	// The store's clock stands still: only kernel's time can end the challenge.
	const { passkeys, answer, advance } = await kept(softwareAuthenticator(), () => 1_000);
	const response = await answer();
	advance(120_000);
	expect(await passkeys.assert(response, "app")).toMatchObject({
		kind: "refused",
		reason: "challenge",
	});
});

it("takes a challenge once", async () => {
	const { passkeys, answer } = await kept();
	const response = await answer();
	expect((await passkeys.assert(response, "app")).kind).toBe("asserted");
	expect(await passkeys.assert(response, "app")).toEqual({ kind: "refused", reason: "challenge" });
});

it("redeems a challenge made for a requester only for that requester, taking it either way", async () => {
	const { passkeys, authenticator } = await kept();
	const ask = async (requester: string) =>
		authenticator.get((await passkeys.challenge(requester)).options as RequestOptions, at);
	const made = await ask("app");
	expect(await passkeys.assert(made, "other")).toEqual({ kind: "refused", reason: "challenge" });
	expect(await passkeys.assert(made, "app")).toEqual({ kind: "refused", reason: "challenge" });
	expect((await passkeys.assert(await ask("app"), "app")).kind).toBe("asserted");
});

it("refuses a challenge kept for no requester, whoever redeems it", async () => {
	const { passkeys, ceremonies, stores, authenticator } = await kept();
	const { options, challenge } = ceremonies.request([], "preferred");
	const record = { v: 1, kind: "assertion", at: 1_000 } as unknown as StoredChallenge;
	await stores.challenges.open(challenge, record, 120_000);
	const response = authenticator.get(options as RequestOptions, at);
	expect(await passkeys.assert(response, "app")).toEqual({ kind: "refused", reason: "challenge" });
});

it("keeps a digest of the requester, of one size whatever its length", async () => {
	const { passkeys, stores } = await kept();
	const { options } = await passkeys.challenge("x".repeat(60_000));
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
	const { options } = await passkeys.challenge("app");
	const unknown = stranger.get(options as RequestOptions, at);
	expect(await passkeys.assert(unknown, "app")).toEqual({
		kind: "refused",
		reason: "unknown-credential",
	});
	const other = randomBytes(32).toString("base64url");
	expect(await passkeys.assert(await answer({ userHandle: other }), "app")).toEqual({
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
	expect(await passkeys.assert(response, "app")).toEqual({ kind: "refused", reason: "raced" });
});

it("answers unavailable when the store cannot tell, never a refusal", async () => {
	const { passkeys, answer, stores } = await kept();
	const response = await answer();
	stores.down.credentials.failNext("read");
	await expect(passkeys.assert(response, "app")).rejects.toSatisfy(isUnavailable);
	stores.down.challenges.failNext("open");
	await expect(passkeys.challenge("app")).rejects.toSatisfy(isUnavailable);
});
