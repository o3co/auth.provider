import { generateKeyPairSync, randomBytes } from "node:crypto";
import { areaTarget, type Started, sceneOf } from "@mod/conformance";
import { afterEach, describe, expect, it } from "vitest";
import { type KeysPart, keysArea, type PreviousKeyScene, type SigningScene } from "../src/main.ts";

const driver = areaTarget();
/** A scene of keys alone. */
type Scene = { readonly keys: KeysPart };
const jwksPath = "/.well-known/jwks.json";
const privateMembers = ["d", "p", "q", "dp", "dq", "qi", "k"];

function eddsa(kid: string): Extract<SigningScene, { alg: "EdDSA" | "ES256" | "RS256" }> {
	const pair = generateKeyPairSync("ed25519");
	return {
		kid,
		alg: "EdDSA",
		privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
		publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
	};
}

function previous(kid: string, expiresAt: string): PreviousKeyScene {
	return { kid, alg: "EdDSA", publicPem: eddsa(kid).publicPem, expiresAt };
}

let running: Started | undefined;
afterEach(async () => {
	if (running?.kind === "running") await running.stop();
	running = undefined;
});

async function serve(scene: Scene): Promise<string> {
	running = await driver.start(sceneOf(keysArea.part(scene.keys)));
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	return running.baseUrl;
}

async function refusal(scene: Scene): Promise<string> {
	running = await driver.start(sceneOf(keysArea.part(scene.keys)));
	expect(running.kind).toBe("refused");
	return running.kind === "refused" ? running.output : "";
}

describe("A. key set", () => {
	it("publishes the current key and unexpired previous keys with public members only", async () => {
		const base = await serve({
			keys: {
				signing: eddsa("current"),
				previous: [
					previous("live", "2099-01-01T00:00:00Z"),
					previous("gone", "2020-01-01T00:00:00Z"),
				],
			},
		});
		const res = await fetch(`${base}${jwksPath}`);
		expect(res.status).toBe(200);
		const { keys } = (await res.json()) as { keys: Record<string, unknown>[] };
		expect(keys.map((k) => k.kid).sort()).toEqual(["current", "live"]);
		for (const key of keys) {
			expect(privateMembers.filter((m) => m in key)).toEqual([]);
			expect(key.kty).not.toBe("oct");
		}
	});

	it("answers with a strong ETag, honours If-None-Match and allows caching", async () => {
		const base = await serve({ keys: { signing: eddsa("current") } });
		const res = await fetch(`${base}${jwksPath}`);
		const etag = res.headers.get("etag") ?? "";
		expect(etag).toMatch(/^"[^"]+"$/);
		expect(res.headers.get("cache-control")).toMatch(/max-age=[1-9]\d*/);
		const same = await fetch(`${base}${jwksPath}`, { headers: { "if-none-match": etag } });
		expect(same.status).toBe(304);
		expect(same.headers.get("etag")).toBe(etag);
		const listed = await fetch(`${base}${jwksPath}`, {
			headers: { "if-none-match": `"other", ${etag}` },
		});
		expect(listed.status).toBe(304);
		const other = await fetch(`${base}${jwksPath}`, { headers: { "if-none-match": '"other"' } });
		expect(other.status).toBe(200);
	});

	it("answers HEAD with the headers of GET and no body", async () => {
		const base = await serve({ keys: { signing: eddsa("current") } });
		// The client closes after a HEAD; the connection's own headers differ for that alone.
		const own = ["date", "connection", "keep-alive"];
		const kept = (res: Response) => [...res.headers].filter(([name]) => !own.includes(name));
		const got = await fetch(`${base}${jwksPath}`);
		const head = await fetch(`${base}${jwksPath}`, { method: "HEAD" });
		expect(head.status).toBe(200);
		expect(await head.text()).toBe("");
		expect(kept(head)).toEqual(kept(got));
	});

	it("does not publish a key set when signing only with a shared secret", async () => {
		const base = await serve({
			keys: { signing: { kid: "h", alg: "HS256", secretHex: randomBytes(32).toString("hex") } },
		});
		const res = await fetch(`${base}${jwksPath}`);
		expect(res.status).toBe(404);
		expect(res.headers.get("cache-control")).toBe("no-store");
	});
});

describe("O. refusals about keys", () => {
	it("refuses to start without signing key material", async () => {
		await refusal({ keys: {} });
	});

	it("refuses a short shared secret without printing it", async () => {
		const secretHex = `5ec7e7${randomBytes(28).toString("hex")}`;
		const output = await refusal({ keys: { signing: { kid: "h", alg: "HS256", secretHex } } });
		expect(output).not.toContain(secretHex);
	});

	it("refuses an empty kid and a kid with a control character", async () => {
		await refusal({ keys: { signing: { ...eddsa("x"), kid: "" } } });
		await refusal({ keys: { signing: { ...eddsa("x"), kid: "a\u0001b" } } });
	});

	it("refuses duplicate kids across current and previous keys", async () => {
		await refusal({
			keys: { signing: eddsa("dup"), previous: [previous("dup", "2099-01-01T00:00:00Z")] },
		});
	});

	it("refuses an unknown setting in the key section", async () => {
		await refusal({ keys: { signing: eddsa("k"), unknownSetting: true } });
	});

	it("never prints private key material when refusing", async () => {
		const signing = eddsa("dup");
		const output = await refusal({
			keys: { signing, previous: [previous("dup", "2099-01-01T00:00:00Z")] },
		});
		const body = signing.privatePem.split("\n")[1] ?? "";
		expect(output).not.toContain(body);
	});
});
