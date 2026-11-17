import { randomBytes } from "node:crypto";
import { isUnavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import { memoryStores } from "../../../test/stores.ts";
import type { StoredChallenge } from "../../store.ts";
import { keptChallenges } from "../challenges.ts";

const fresh = () => randomBytes(32).toString("base64url");
const held = (value: object) => value as unknown as StoredChallenge;
const registering = { kind: "registration", subject: "sam" } as const;
const asserting = { kind: "assertion", by: "login", requester: "r" } as const;

function routed() {
	const stores = memoryStores();
	const challenges = keptChallenges(stores.challenges, () => 0, 120_000, stores.registrations);
	return { stores, challenges };
}

it("keeps a registration's challenge in the registration challenge store, for its subject, and takes it once", async () => {
	const { stores, challenges } = routed();
	const challenge = fresh();
	await challenges.open(challenge, registering);
	expect(await stores.challenges.take(challenge, held({}))).toBeUndefined();
	expect(await challenges.take(challenge, "registration")).toEqual({ ...registering, at: 0 });
	expect(await challenges.take(challenge, "registration")).toBeUndefined();
});

it("keeps an assertion's challenge in the challenge store, the registration challenge store unasked", async () => {
	const { stores, challenges } = routed();
	const challenge = fresh();
	await challenges.open(challenge, asserting);
	expect(await stores.registrations.update(challenge, () => undefined)).toBeUndefined();
	expect(await challenges.take(challenge, "assertion")).toEqual({ ...asserting, at: 0 });
});

it("takes a registration's challenge from the challenge store where the registration challenge store holds none, as 0.19 opened it", async () => {
	const { stores, challenges } = routed();
	const challenge = fresh();
	await keptChallenges(stores.challenges, () => 0, 120_000).open(challenge, registering);
	expect(await challenges.take(challenge, "registration")).toEqual({ ...registering, at: 0 });
	expect(await challenges.take(challenge, "registration")).toBeUndefined();
	expect(await challenges.take(fresh(), "registration")).toBeUndefined();
});

it("answers a registration from its taken mark, the challenge store unread", async () => {
	const { stores, challenges } = routed();
	const challenge = fresh();
	await challenges.open(challenge, registering);
	await stores.challenges.open(challenge, held({ v: 2, ...registering, at: 0 }), 120_000);
	expect(await challenges.take(challenge, "registration")).toEqual({ ...registering, at: 0 });
	expect(await challenges.take(challenge, "registration")).toBeUndefined();
	// The one in the challenge store is left as it was.
	expect((await stores.challenges.take(challenge, held({})))?.before).toEqual(
		held({ v: 2, ...registering, at: 0 }),
	);
});

it("opens no registration challenge for a subject the store fences, as unavailable", async () => {
	const { stores, challenges } = routed();
	stores.fence("sam");
	await expect(challenges.open(fresh(), registering)).rejects.toSatisfy(isUnavailable);
	await challenges.open(fresh(), { kind: "registration", subject: "kim" });
});

it("keeps every challenge in the challenge store where no registration challenge store is composed", async () => {
	const stores = memoryStores(() => 0, { registrations: false });
	const challenges = keptChallenges(stores.challenges, () => 0, 120_000);
	const challenge = fresh();
	await challenges.open(challenge, registering);
	expect(await stores.registrations.update(challenge, () => undefined)).toBeUndefined();
	expect(await challenges.take(challenge, "registration")).toEqual({ ...registering, at: 0 });
});
