import { randomBytes } from "node:crypto";
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
import { passkeysOver } from "../src/passkeys.ts";
import { keptChallenges, keptPasskeys } from "../src/records.ts";
import { heldState, memoryStores, writeToken } from "./stores.ts";

const at = { origin: testOrigin };
const rp = { id: "rp.example", name: "RP", origins: [testOrigin], topOrigins: [], timeoutMs: 1000 };

/**
 * Sam registers a credential id; once sam's write has read and decided, kim registers the same id
 * with another key, and `kimsWrite` says whether kim's write lands. Sam's write decides again.
 */
async function raced(kimsWrite: "lands" | "fails") {
	const stores = memoryStores(() => 1_000);
	const ceremonies = ceremoniesFor(
		rp,
		(n) => new Uint8Array(randomBytes(n)),
		() => 1_000,
	);
	const records = keptPasskeys(stores.passkeys, writeToken);
	const challenges = keptChallenges(stores.challenges, () => 1_000, 120_000);
	const passkeys = passkeysOver({ ceremonies, records, challenges, verification: "preferred" });
	const id = randomBytes(16).toString("base64url");
	const madeFor = async (
		subject: string,
		authenticator: ReturnType<typeof softwareAuthenticator>,
	) => {
		const handle = await records.handleFor(subject, randomBytes(32).toString("base64url"));
		const { options, challenge } = ceremonies.creation({ handle, name: subject }, [], "preferred");
		const response = authenticator.create(options as CreationOptions, at, { credentialId: id });
		const made = await ceremonies.attest(response, challenge, handle, "preferred");
		return (made as { credential: Credential }).credential;
	};
	const [samsKey, kimsKey] = [softwareAuthenticator(), softwareAuthenticator()];
	const [sams, kims] = [await madeFor("sam", samsKey), await madeFor("kim", kimsKey)];
	stores.raceNextTogether(async () => {
		if (kimsWrite === "lands") {
			expect(await records.register("kim", kims, 10)).toBe("registered");
		} else {
			stores.down.together.failNext("updateTogether");
			await expect(records.register("kim", kims, 10)).rejects.toSatisfy(isUnavailable);
		}
	});
	const samsAnswer = await records.register("sam", sams, 10);
	const login = async (authenticator: ReturnType<typeof softwareAuthenticator>) => {
		const { options } = await passkeys.challenge("app");
		return passkeys.assert(authenticator.get(options as RequestOptions, at), "app");
	};
	// What the store holds, read raw before any later write.
	const held = await heldState(stores.passkeys, ["sam", "kim"], [id]);
	return { records, login, samsAnswer, held, samsKey, kimsKey, kims, id };
}

it("lets in only the holder whose write landed first, the other's deciding again to a conflict", async () => {
	const { records, login, samsAnswer, held, samsKey, kimsKey, id } = await raced("lands");
	expect(samsAnswer).toBe("conflict");
	expect(held).toEqual({
		lists: { sam: [], kim: [id] },
		records: { [id]: { subject: "kim", as: "passkey" } },
	});
	expect((await records.holder("sam"))?.credentials).not.toContain(id);
	expect((await records.passkey(id))?.subject).toBe("kim");
	expect(await login(samsKey)).toMatchObject({ kind: "refused" });
	expect(await login(kimsKey)).toMatchObject({ kind: "asserted", subject: "kim" });
});

it("lets in the holder whose write landed where the other's failed, which then finds it held", async () => {
	const { records, login, samsAnswer, held, samsKey, kimsKey, kims, id } = await raced("fails");
	expect(samsAnswer).toBe("registered");
	expect(held).toEqual({
		lists: { sam: [id], kim: [] },
		records: { [id]: { subject: "sam", as: "passkey" } },
	});
	expect(await login(samsKey)).toMatchObject({ kind: "asserted", subject: "sam" });
	expect(await login(kimsKey)).toMatchObject({ kind: "refused" });
	expect(await records.register("kim", kims, 10)).toBe("conflict");
});
