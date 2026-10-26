import { generateKeyPairSync } from "node:crypto";
import { createServer } from "node:http";
import { describe, expect, it } from "vitest";
import { identityDifferences, identityOf } from "../identity.ts";

/** An instance's public JWK, of a fresh Ed25519 key, under `kid`. */
const jwkOf = (kid: string) => ({
	...generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }),
	kid,
});

/** What a server answers at `/keys`: a status and a body as written. */
type KeysAnswer = { readonly status: number; readonly body: string };

/**
 * A server publishing `metadata` at `metadataPath` alone, naming `/keys` as its key set unless
 * `jwks` is false, and `keys` there (or `answer` as written); every other path is 404.
 */
async function publishing(
	metadataPath: string,
	issuer: string,
	keys: readonly object[],
	{ jwks = true, answer }: { jwks?: boolean; answer?: KeysAnswer } = {},
) {
	const server = createServer((req, res) => {
		const metadata = jwks ? { issuer, jwks_uri: "https://as.example/keys" } : { issuer };
		const written =
			req.url === metadataPath
				? { status: 200, body: JSON.stringify(metadata) }
				: req.url === "/keys"
					? (answer ?? { status: 200, body: JSON.stringify({ keys }) })
					: { status: 404, body: "" };
		res.writeHead(written.status, { "content-type": "application/json" }).end(written.body);
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address();
	const port = typeof address === "object" && address ? address.port : 0;
	return { base: `http://127.0.0.1:${port}`, stop: () => new Promise((r) => server.close(r)) };
}

describe("the instances of a deployment", () => {
	it("are one deployment only where each names the same issuer and keys", () => {
		const one = { issuer: "https://as.example", keys: ["k1#a", "k2#b"] };
		expect(identityDifferences([one, one])).toEqual([]);
		expect(identityDifferences([one, { ...one, issuer: "https://other.example" }])).toEqual([
			"instance 1 names the issuer https://other.example, instance 0 https://as.example",
		]);
		expect(identityDifferences([one, { ...one, keys: ["k1#a"] }])).toEqual([
			"instance 1 publishes the keys k1#a, instance 0 k1#a, k2#b",
		]);
	});

	it("are compared only where each publishes, and all alike: one that does not, beside one that does, differs", () => {
		expect(identityDifferences([null, null])).toEqual([]);
		expect(identityDifferences([{ issuer: "https://as.example", keys: [] }, null])).toEqual([
			"instance 1 publishes no metadata, instance 0 does",
		]);
	});

	it("reads an issuer with a path where it publishes, under the path, and its keys where its metadata says", async () => {
		const issuer = "https://as.example/tenant/a";
		const key = jwkOf("k1");
		for (const at of [
			"/tenant/a/.well-known/openid-configuration",
			"/.well-known/oauth-authorization-server/tenant/a",
		]) {
			const server = await publishing(at, issuer, [key]);
			const read = await identityOf(server.base, issuer);
			expect(read?.issuer, at).toBe(issuer);
			expect(read?.keys, at).toEqual([expect.stringMatching(/^k1#[A-Za-z0-9_-]{43}$/)]);
			await server.stop();
		}
	});

	it("tells keys apart by what they are, not by their ids alone", async () => {
		const issuer = "https://as.example";
		const [a, b] = [
			await publishing("/.well-known/openid-configuration", issuer, [jwkOf("k1")]),
			await publishing("/.well-known/openid-configuration", issuer, [jwkOf("k1")]),
		];
		const differences = identityDifferences([
			await identityOf(a.base, issuer),
			await identityOf(b.base, issuer),
		]);
		expect(differences).toEqual([expect.stringMatching(/^instance 1 publishes the keys k1#/)]);
		await a.stop();
		await b.stop();
	});

	it("reads no keys where the metadata names no key set, or the set it names is empty", async () => {
		const issuer = "https://as.example";
		for (const [keys, jwks] of [
			[[], true],
			[[jwkOf("k1")], false],
		] as const) {
			const server = await publishing("/.well-known/openid-configuration", issuer, keys, { jwks });
			expect(await identityOf(server.base, issuer)).toEqual({ issuer, keys: [] });
			await server.stop();
		}
	});

	it("refuses a key set its metadata names that cannot be read, rather than taking it as empty", async () => {
		const issuer = "https://as.example";
		for (const answer of [
			{ status: 404, body: "" },
			{ status: 500, body: JSON.stringify({ keys: [] }) },
			{ status: 200, body: JSON.stringify({ key: [] }) },
			{ status: 200, body: JSON.stringify({ keys: {} }) },
			{ status: 200, body: "not json" },
		]) {
			const server = await publishing("/.well-known/openid-configuration", issuer, [], { answer });
			await expect(identityOf(server.base, issuer), answer.body).rejects.toThrow(
				/the key set https:\/\/as\.example\/keys/,
			);
			await server.stop();
		}
	});
});
