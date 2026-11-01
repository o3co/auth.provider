import { createHash, generateKeyPairSync } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { type AreaScene, area, areaTarget, onNew, type Started } from "@mod/conformance";
import { onLegacy } from "@mod/conformance-legacy";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { codeScene } from "../../main.ts";
import { browserAt } from "../../testing.ts";

// The app's outbound proxy: it records each destination asked of it and opens none.
const proxyArea = area<{ readonly proxy: string }>("documents-proxy");
onNew(proxyArea, (part) => ({ config: { outbound: { proxy: part.proxy } } }));
onLegacy(proxyArea, { map: () => ({}), cannot: ["outbound-proxy"] });

const issuer = "https://issuer.example";
const documentId = "https://docs.example/client.json";
const pair = generateKeyPairSync("ed25519");
const user = { identifier: "alice", password: "correct horse battery" };
const sceneOf = (proxy: string): AreaScene => {
	const scene = codeScene({
		issuer,
		keys: {
			signing: {
				kid: "dl",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		},
		clients: [],
		users: [user],
		discovery: true,
		// The back channel's one origin, which outbound reaches over plain http at loopback.
		logout: { allowed: ["http://127.0.0.1:9"] },
		documents: { allow: ["docs.example"], scopes: ["openid"] },
	});
	return { ...scene, parts: { ...scene.parts, [proxyArea.name]: { proxy } } };
};

describe.runIf(areaTarget().can("outbound-proxy"))(
	"metadata document clients beside a logout's back channel",
	() => {
		const asked: string[] = [];
		const proxy = createServer();
		proxy.on("connect", (req, socket) => {
			asked.push(req.url ?? "");
			socket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
		});
		let running: Started;
		let base = "";
		beforeAll(async () => {
			await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
			const port = (proxy.address() as AddressInfo).port;
			running = await areaTarget().start(sceneOf(`http://127.0.0.1:${port}`));
			if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
			base = running.baseUrl;
		});
		afterAll(async () => {
			if (running?.kind === "running") await running.stop();
			await new Promise((resolve) => proxy.close(resolve));
		});

		it("fetches a document from an allowed host, which outbound reaches beside the back channel's origin", async () => {
			const browser = browserAt(() => base, issuer, {
				username: user.identifier,
				password: user.password,
			});
			await browser.authorize({
				response_type: "code",
				client_id: documentId,
				redirect_uri: "https://docs.example/cb",
				state: "s1",
				scope: "openid",
				code_challenge: createHash("sha256").update("d".repeat(43)).digest("base64url"),
				code_challenge_method: "S256",
			});
			expect(asked).toContain("docs.example:443");
		});
	},
);
