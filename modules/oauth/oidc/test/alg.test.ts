import { generateKeyPairSync } from "node:crypto";
import { type DocumentCopy, documentCopies } from "@mod/client-documents";
import { clients } from "@mod/clients";
import clientsModule from "@mod/clients/module";
import { clientsConfig, publicClient } from "@mod/clients/testing";
import { contract, defineModule } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { describe, expect, it } from "vitest";
import { booted, makers, published } from "./parts.ts";

const runtime = quietRuntime();

const rsaSigning = () => ({
	kid: "r",
	alg: "RS256",
	"private-key": generateKeyPairSync("rsa", { modulusLength: 2048 })
		.privateKey.export({ type: "pkcs8", format: "pem" })
		.toString(),
});

const copies = contract<readonly DocumentCopy[]>("copies");
const copiesSeen = defineModule(
	{ name: "copies-probe", replicaSafe: true, takes: [documentCopies] },
	(m) => [m.provide(copies).by((c) => c.collect(documentCopies))],
);

/** oidc with clients, these registered, and the configuration given. */
const withClients = (registered: readonly unknown[], config: Record<string, unknown> = {}) =>
	booted({
		runtime,
		more: [clientsModule, copiesSeen],
		config: { ...clientsConfig(registered as never), ...config },
	});

const algOf = (token: string) =>
	JSON.parse(Buffer.from(token.split(".")[0] ?? "", "base64url").toString()).alg;

const request = {
	subject: "a",
	clientId: "c",
	authenticatedAt: 0,
	amr: [],
	scope: ["openid"],
	session: "s",
	redemption: "r-test",
};

describe("the algorithm the operator fixes", () => {
	it("is the one keys signs with, unset or written the same [oidc-core-10.1-a]", async () => {
		for (const config of [{}, { oidc: { "id-token-alg": "EdDSA" } }]) {
			const [maker] = (await booted({ runtime, config })).get(makers);
			expect(algOf((await maker?.make(request)) ?? "")).toBe("EdDSA");
		}
	});

	it("refuses to start where keys does not sign with it, naming the algorithm keys signs with", async () => {
		await expect(
			booted({ runtime, config: { oidc: { "id-token-alg": "RS256" } } }),
		).rejects.toMatchObject({
			refusals: [
				{
					where: "oidc.id-token-alg",
					reason:
						"keys signs ID tokens with EdDSA: set keys.signing.alg to this one, or leave this unset",
				},
			],
		});
	});
});

describe("the algorithm a client registers for its ID tokens [oidc-core-10.1-a]", () => {
	it("is keys' algorithm when the client registers none", async () => {
		const app = await withClients([publicClient({ id: "c" })]);
		const [maker] = app.get(makers);
		expect(algOf((await maker?.make(request)) ?? "")).toBe("EdDSA");
		expect((await app.get(clients).find("c"))?.registered).toBe(true);
	});

	it("is the one it registers, where that is keys' algorithm", async () => {
		const registered = publicClient({ id: "c", sections: { oidc: { "id-token-alg": "EdDSA" } } });
		const app = await withClients([registered]);
		const [maker] = app.get(makers);
		expect(algOf((await maker?.make(request)) ?? "")).toBe("EdDSA");
	});

	it("refuses to start where a registered client names another, by its place and the algorithm alone", async () => {
		const registered = publicClient({
			id: "the-client",
			sections: { oidc: { "id-token-alg": "RS256" } },
		});
		const refused = withClients([registered]);
		await expect(refused).rejects.toMatchObject({
			refusals: [
				{
					where: "clients.registered.0.sections.oidc.id-token-alg",
					reason: "ID tokens are signed with EdDSA alone",
				},
			],
		});
		await expect(refused).rejects.not.toThrow(/the-client/);
	});

	it("is taken from a metadata document's id_token_signed_response_alg, and refused where it is another", async () => {
		const app = await withClients([]);
		const copy = app.get(copies).find((one) => one.section.name === "oidc");
		expect(copy?.reads).toEqual(["id_token_signed_response_alg"]);
		const from = { id: "https://rp.example/client", host: "rp.example" };
		expect(copy?.copy({}, from)).toBeUndefined();
		const recordOf = (alg: unknown) => {
			const copied = copy?.copy({ id_token_signed_response_alg: alg }, from);
			if (!copied || !("value" in copied)) throw new Error("no value copied");
			return {
				id: from.id,
				kind: "public",
				method: "none",
				sections: { oidc: copied.value },
			} as const;
		};
		const check = app.get(clients).checkRecord;
		expect(await check(recordOf("EdDSA"))).toBeUndefined();
		for (const alg of ["RS256", "none", 256]) {
			expect(await check(recordOf(alg)), String(alg)).toEqual([
				{ path: "sections.oidc.id-token-alg" },
			]);
		}
	});
});

describe("a deployment whose ID tokens are not signed with RS256", () => {
	it("is warned of it once each boot, by the algorithm's name alone [oidc-discovery-3-aa]", async () => {
		const recording = recordingLog();
		const app = await booted({ runtime: quietRuntime({ log: recording.log }) });
		app.get(makers);
		app.get(published);
		expect(recording.lines().filter((line) => line.level === "warn")).toEqual([
			{ level: "warn", event: "oidc.id_token_alg_not_rs256", fields: { alg: "EdDSA" } },
		]);
	});

	it("is not warned where keys signs with RS256", async () => {
		const recording = recordingLog();
		await booted({
			runtime: quietRuntime({ log: recording.log }),
			config: { keys: { signing: rsaSigning() } },
		});
		expect(recording.lines().filter((line) => line.level === "warn")).toEqual([]);
	});
});
