import { randomBytes } from "node:crypto";
import { isUnavailable } from "@mod/kernel";
import type { Credential, PasskeyStore } from "@mod/webauthn";
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
import { memoryStores } from "./stores.ts";

const at = { origin: testOrigin };
const rp = { id: "rp.example", name: "RP", origins: [testOrigin], topOrigins: [], timeoutMs: 1000 };

/**
 * Sam registers a credential id; between keeping it and listing it, kim registers the same id
 * with another key, and `kimsListing` says whether kim's listing lands.
 */
async function raced(kimsListing: "lands" | "fails") {
	const stores = memoryStores(() => 1_000);
	let between: (() => Promise<void>) | undefined;
	const paused: PasskeyStore = {
		credentials: stores.passkeys.credentials,
		subjects: {
			...stores.passkeys.subjects,
			update: async (key, change) => {
				const run = between;
				between = undefined;
				await run?.();
				return stores.passkeys.subjects.update(key, change);
			},
		},
	};
	const ceremonies = ceremoniesFor(
		rp,
		(n) => new Uint8Array(randomBytes(n)),
		() => 1_000,
	);
	const records = keptPasskeys(paused);
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
	between = async () => {
		if (kimsListing === "lands") {
			expect(await records.register("kim", kims, 10)).toBe("registered");
		} else {
			stores.down.subjects.failNext("update");
			await expect(records.register("kim", kims, 10)).rejects.toSatisfy(isUnavailable);
		}
	};
	// Sam's registration is answered as kept, though kim took the id meanwhile.
	expect(await records.register("sam", sams, 10)).toBe("registered");
	expect((await records.holder("sam"))?.credentials).toContain(id);
	const login = async (authenticator: ReturnType<typeof softwareAuthenticator>) => {
		const { options } = await passkeys.challenge("app");
		return passkeys.assert(authenticator.get(options as RequestOptions, at), "app");
	};
	return { records, login, samsKey, kimsKey, kims, id };
}

it("lets in only the holder the credential record names and whose list holds the id", async () => {
	const { records, login, samsKey, kimsKey, id } = await raced("lands");
	expect((await records.passkey(id))?.subject).toBe("kim");
	expect(await login(samsKey)).toMatchObject({ kind: "refused" });
	expect(await login(kimsKey)).toMatchObject({ kind: "asserted", subject: "kim" });
});

it("lets nobody in while the id is on no list of the holder its record names", async () => {
	const { records, login, samsKey, kimsKey, kims } = await raced("fails");
	expect(await login(samsKey)).toEqual({ kind: "refused", reason: "unknown-credential" });
	expect(await login(kimsKey)).toEqual({ kind: "refused", reason: "unknown-credential" });
	expect(await records.register("kim", kims, 10)).toBe("registered");
	expect(await login(kimsKey)).toMatchObject({ kind: "asserted", subject: "kim" });
	expect(await login(samsKey)).toMatchObject({ kind: "refused" });
});
