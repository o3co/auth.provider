import { generateKeyPairSync } from "node:crypto";
import { createServer } from "node:http";
import { describe, expect, it } from "vitest";
import { identityDifferences, identityOf } from "../identity.ts";

/** An instance's public JWK, of a fresh Ed25519 key, under `kid`. */
const jwkOf = (kid: string) => ({
	...generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }),
	kid,
});

/** A server publishing `metadata` at `metadataPath` alone and `keys` at `/keys`; every other path is 404. */
async function publishing(metadataPath: string, issuer: string, keys: readonly object[]) {
	const server = createServer((req, res) => {
		const body =
			req.url === metadataPath
				? { issuer, jwks_uri: "https://as.example/keys" }
				: req.url === "/keys"
					? { keys }
					: undefined;
		if (!body) {
			res.writeHead(404).end();
			return;
		}
		res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(body));
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
});
