import { createHash, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { type MetadataItem, metadata } from "@mod/issuer";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
} from "@mod/kernel";
import { quietRuntime, recordingLog, takesUnused, unavailableSwitch } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import { type SenderBinding, senderBinding, senderBindings } from "@mod/sender-binding";
import senderBindingModule from "@mod/sender-binding/module";
import { calculateJwkThumbprint, exportJWK, SignJWT } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import dpop from "../src/module.ts";
import { type SpentProofs, spentProofs } from "../src/store.ts";

let shift = 0;
afterEach(() => {
	shift = 0;
});
const runtime = quietRuntime({ clock: { now: () => Date.now() + shift } });
const holder = generateKeyPairSync("ed25519");
const issuer = "https://as.example";
/** dpop's spent proofs in memory, on the composition's clock, keeping the lifetimes asked for, behind a switch. */
function spentInMemory() {
	const stand = memoryRecords<true>(() => runtime.clock.now(), { shards: 1, perShard: 1 });
	const lifetimes: number[] = [];
	const down = unavailableSwitch<SpentProofs>("spent proofs");
	const module = defineModule({ name: "spent-proofs", replicaSafe: false, takes: [] }, (m) => [
		m.provide(spentProofs).by(() =>
			down.wrap({
				save: (name: string, lifetimeMs: number) => {
					lifetimes.push(lifetimeMs);
					return stand.records.create(name, true, lifetimeMs);
				},
			}),
		),
	]);
	return { module, lifetimes, down };
}

const published = contract<readonly MetadataItem[]>("published");
const kinds = contract<readonly SenderBinding[]>("kinds");
const reader = defineModule(
	{ name: "reader", replicaSafe: true, takes: [metadata, senderBindings] },
	(m) => [
		m.provide(published).by((c) => c.collect(metadata)),
		m.provide(kinds).by((c) => c.collect(senderBindings)),
	],
);

/** The assembly of a composition with dpop, its section where given (else asking no nonce), and the issuer at `at`. */
const assembly = (dpopSection?: unknown, spent = spentInMemory(), at = issuer) => ({
	modules: [http, issuerModule, senderBindingModule, dpop, reader, spent.module],
	config: {
		...kernelConfig(),
		...httpConfig(),
		...issuerConfig({ url: at }),
		dpop: dpopSection ?? { nonce: { required: "never" } },
	},
	runtime,
});

/** A composition with dpop, its section where given, and the issuer at `at`. */
const boot = (...given: Parameters<typeof assembly>) => assemble(assembly(...given));

const publishedAlgorithms = async (dpopSection?: unknown) =>
	(await boot(dpopSection))
		.get(published)
		.find((item) => item.name === "dpop_signing_alg_values_supported")?.value;

/** Reads a request to the token endpoint carrying this proof, as the endpoint does at issuance. */
async function serve(spent = spentInMemory(), at = issuer) {
	const app = await boot(undefined, spent, at);
	const token = (dpopProof?: string, path = "/oauth/token") =>
		app.get(senderBinding).bindingOf(
			testRequest({
				method: "POST",
				path,
				headers: new Map(dpopProof === undefined ? [] : [["dpop", dpopProof]]),
			}),
			{ kind: "issue" },
		);
	return Object.assign(token, { app });
}

const bound = { kind: "bound", binding: { member: "jkt", tokenType: "DPoP" } };
const replayed = {
	kind: "refused",
	error: "invalid_dpop_proof",
	description: "proof used before",
};

async function proof({
	jti = randomUUID(),
	iat = Math.floor(runtime.clock.now() / 1000),
	key = holder,
	htm = "POST",
	htu = `${issuer}/oauth/token`,
	ath = undefined as string | undefined,
	nonce = undefined as string | undefined,
} = {}) {
	return new SignJWT({ htm, htu, iat, jti, ath, ...(nonce === undefined ? {} : { nonce }) })
		.setProtectedHeader({ alg: "EdDSA", typ: "dpop+jwt", jwk: await exportJWK(key.publicKey) })
		.sign(key.privateKey);
}

describe("dpop", () => {
	it("declares its proof explicit, so it wins over a certificate a request also proves, and is named dpop for operators", async () => {
		const app = await boot();
		const dpop = app.get(kinds).find((kind) => kind.member === "jkt");
		expect([dpop?.explicit, dpop?.name]).toEqual([true, "dpop"]);
	});

	it("names among the issuer's metadata the algorithms it takes proofs in", async () => {
		const section = { algorithms: ["ES256", "EdDSA"], nonce: { required: "never" } };
		expect(await publishedAlgorithms(section)).toEqual(["ES256", "EdDSA"]);
	});

	it("names all four algorithms by default", async () => {
		expect(await publishedAlgorithms()).toEqual(["ES256", "ES384", "EdDSA", "RS256"]);
	});

	it("refuses a section outside its bounds [rfc9449-11.6-a] [rfc9449-11.6-b]", async () => {
		for (const refused of [
			{ algorithms: ["HS256"] },
			{ algorithms: [] },
			{ "proof-window": "0s" },
			{ "proof-window": "301s" },
			{ "proof-window": "1500ms" },
			{ "proof-window": 60 },
			{ other: true },
		]) {
			await expect(boot(refused), JSON.stringify(refused)).rejects.toThrow();
		}
		const never = { required: "never" };
		expect((await boot({ "proof-window": "5m", nonce: never })).get(senderBinding)).toBeDefined();
	});

	it("asks a nonce at the token endpoint by default, so boot needs the nonce's secret", async () => {
		const refused = await boot({}).catch((error: unknown) => error);
		expect((refused as BootRefused).refusals.map((r) => r.where)).toEqual(["dpop.nonce.secret"]);
		const secret = randomBytes(32).toString("base64");
		await expect(boot({ nonce: { secret } })).resolves.toBeDefined();
	});

	it("reads none from a request without a proof, spending nothing", async () => {
		const spent = spentInMemory();
		const token = await serve(spent);
		expect(await token()).toEqual({ kind: "none" });
		expect(spent.lifetimes).toEqual([]);
	});

	it("confirms the key by its thumbprint, judged on the composition's clock", async () => {
		const token = await serve();
		shift = 600_000;
		const read = await token(await proof());
		expect(read).toMatchObject(bound);
		expect(read).toMatchObject({
			binding: { confirmation: await calculateJwkThumbprint(await exportJWK(holder.publicKey)) },
		});
	});

	it("takes htu from the issuer's origin and the request's path", async () => {
		const token = await serve(spentInMemory(), `${issuer}/tenant`);
		const htu = `${issuer}/tenant/oauth/token`;
		expect(await token(await proof({ htu }), "/tenant/oauth/token")).toMatchObject(bound);
	});

	it("binds a token to the proof's key, and accepts each proof once", async () => {
		const token = await serve();
		const once = await proof();
		expect(await token(once)).toMatchObject(bound);
		expect(await token(once)).toEqual(replayed);
		expect(await token(await proof())).toMatchObject(bound);
	});

	it("keeps a jti spent for its own key only", async () => {
		const token = await serve();
		const jti = randomUUID();
		expect(await token(await proof({ jti }))).toMatchObject(bound);
		const other = generateKeyPairSync("ed25519");
		expect(await token(await proof({ jti, key: other }))).toMatchObject(bound);
		expect(await token(await proof({ jti }))).toEqual(replayed);
	});

	it("still refuses a replay at the far edge of the window", async () => {
		const token = await serve();
		// Accepted as early as possible, a minute before its iat, then replayed as late as possible.
		const iat = Math.floor(runtime.clock.now() / 1000) + 60;
		const early = await proof({ iat });
		expect(await token(early)).toMatchObject(bound);
		shift += 118_000;
		// The window still holds, so a refusal can only come from the record.
		expect(await token(await proof({ iat }))).toMatchObject(bound);
		expect(await token(early)).toEqual(replayed);
	});

	it("keeps a proof spent for twice its window and an allowance for the store's clock", async () => {
		const spent = spentInMemory();
		const token = await serve(spent);
		await token(await proof());
		expect(spent.lifetimes).toEqual([2 * 60_000 + 60_000]);
	});

	it("does not use up a proof refused for its ath", async () => {
		const t = (await serve()).app.get(senderBinding);
		const jti = randomUUID();
		const at = async (ath?: string) =>
			t.bindingOf(
				testRequest({
					path: "/resource",
					headers: new Map([
						["dpop", await proof({ jti, htm: "GET", htu: `${issuer}/resource`, ath })],
					]),
				}),
				{ kind: "resource", token: "at" },
			);
		expect(await at()).toMatchObject({ description: "ath does not match the token" });
		expect((await at(createHash("sha256").update("at").digest("base64url"))).kind).toBe("bound");
	});

	it("is unavailable when it cannot record the proof", async () => {
		const spent = spentInMemory();
		const token = await serve(spent);
		spent.down.failNext("save");
		await expect(token(await proof())).rejects.toSatisfy(isUnavailable);
	});
});

describe("server nonces (RFC 9449 §8)", () => {
	const secret = randomBytes(32).toString("base64");
	const bucketMs = 300_000;
	/** A composition asking nonces where `required` says, reading at issuance or at a resource. */
	async function asking(required: "never" | "as" | "as+rs") {
		const app = await boot({ nonce: { required, ttl: `${bucketMs / 1000}s`, secret } });
		return (dpopProof: string, scene: { kind: "issue" } | { kind: "resource"; token: string }) =>
			app.get(senderBinding).bindingOf(
				testRequest({
					method: "POST",
					path: scene.kind === "issue" ? "/oauth/token" : "/api",
					headers: new Map([["dpop", dpopProof]]),
				}),
				scene,
			);
	}
	const issue = { kind: "issue" } as const;
	const token = "at-1";
	const atResource = { kind: "resource", token } as const;
	const ath = createHash("sha256").update(token).digest("base64url");
	const toResource = () => proof({ htu: `${issuer}/api`, ath });
	const askedAgain = { kind: "refused", error: "use_dpop_nonce" };
	/** A nonce given, forged, or written otherwise than it was given: padded, with a stray character, a leading zero, a space. */
	const notGiven = (given: string) => [
		"forged",
		`${given.split(".")[0]}.AAAA`,
		`${given} `,
		`${given}=`,
		`${given}!`,
		`0${given}`,
		given.replace(".", ". "),
	];

	it("refuses a proof without the current nonce as use_dpop_nonce, giving it, and spends no jti [rfc9449-4.2-e] [rfc9449-4.3-h]", async () => {
		// Starts at a bucket's edge, so the clock never crosses one by chance within the test.
		shift = bucketMs - (Date.now() % bucketMs) + 1;
		const read = await asking("as");
		const jti = randomUUID();
		const first = await read(await proof({ jti }), issue);
		if (first.kind !== "refused" || first.error !== "use_dpop_nonce") throw new Error(first.kind);
		const given = first.headers?.["dpop-nonce"] ?? "";
		expect(given).toMatch(/^\d+\.[A-Za-z0-9_-]+$/);
		expect(await read(await proof({ jti, nonce: given }), issue)).toMatchObject(bound);
		for (const wrong of notGiven(given)) {
			expect(await read(await proof({ nonce: wrong }), issue), wrong).toMatchObject({
				...askedAgain,
				headers: { "dpop-nonce": given },
			});
		}
		// A nonce lives through its bucket and the next, then is refused.
		shift += bucketMs;
		expect(await read(await proof({ nonce: given }), issue)).toMatchObject(bound);
		shift += bucketMs;
		expect(await read(await proof({ nonce: given }), issue)).toMatchObject(askedAgain);
	});

	it("takes at a resource under as+rs only the very nonce it gave [rfc9449-4.3-t]", async () => {
		shift = bucketMs - (Date.now() % bucketMs) + 1;
		const read = await asking("as+rs");
		const first = await read(await toResource(), atResource);
		if (first.kind !== "refused" || first.error !== "use_dpop_nonce") throw new Error(first.kind);
		const given = first.headers?.["dpop-nonce"] ?? "";
		const withNonce = (nonce: string) => proof({ htu: `${issuer}/api`, ath, nonce });
		expect(await read(await withNonce(given), atResource)).toMatchObject(bound);
		for (const wrong of notGiven(given)) {
			expect(await read(await withNonce(wrong), atResource), wrong).toMatchObject({
				...askedAgain,
				headers: { "dpop-nonce": given },
			});
		}
	});

	it("asks no nonce at a resource under as", async () => {
		expect(await (await asking("as"))(await toResource(), atResource)).toMatchObject(bound);
	});

	it("asks one at a resource too under as+rs", async () => {
		expect(await (await asking("as+rs"))(await toResource(), atResource)).toMatchObject(askedAgain);
	});

	it("challenges a resource's request without the nonce in the DPoP scheme as use_dpop_nonce, giving a fresh one [rfc9449-4.2-l]", async () => {
		shift = bucketMs - (Date.now() % bucketMs) + 1;
		const app = await boot({ nonce: { required: "as+rs", ttl: `${bucketMs / 1000}s`, secret } });
		const jkt = await calculateJwkThumbprint(await exportJWK(holder.publicKey));
		const tokens = {
			verifyAccess: async () =>
				({
					kind: "valid",
					binding: { member: "jkt", confirmation: jkt, tokenType: "DPoP" },
				}) as const,
		};
		const presenting = async (nonce?: string) =>
			app.get(senderBinding).admitted(
				testRequest({
					method: "POST",
					path: "/api",
					headers: new Map([
						["authorization", `DPoP ${token}`],
						["dpop", await proof({ htu: `${issuer}/api`, ath, nonce })],
					]),
				}),
				tokens,
			);
		const first = await presenting();
		expect(first).toEqual({
			kind: "refused",
			status: 401,
			error: "use_dpop_nonce",
			headers: {
				"www-authenticate": 'DPoP error="use_dpop_nonce"',
				"dpop-nonce": expect.stringMatching(/^\d+\.[A-Za-z0-9_-]+$/),
			},
		});
		const given = first.kind === "refused" ? first.headers["dpop-nonce"] : undefined;
		expect((await presenting(given)).kind).toBe("admitted");
	});

	it("asks none anywhere under never", async () => {
		expect(await (await asking("never"))(await proof(), issue)).toMatchObject(bound);
	});

	it("asks the nonce before the token's hash at a resource, as 0.17 did", async () => {
		const unmatched = await proof({ htu: `${issuer}/api`, ath: "not-the-hash" });
		expect(await (await asking("as+rs"))(unmatched, atResource)).toMatchObject(askedAgain);
	});

	it("refuses to boot asking nonces without a strong shared secret, naming the setting and never the value", async () => {
		const weak = [
			undefined,
			Buffer.alloc(16, 7).toString("base64"),
			"A".repeat(44),
			"REPLACE-32-RANDOM-BYTES-BASE64-ENCODED-PLEASE",
			"correct horse battery staple and a few more words",
		];
		for (const secret of weak) {
			const refused = await boot({ nonce: { required: "as", ...(secret ? { secret } : {}) } }).then(
				() => undefined,
				(error: unknown) => error,
			);
			expect(refused, String(secret)).toBeInstanceOf(BootRefused);
			const where = (refused as BootRefused).refusals.map((r) => r.where);
			expect(where, String(secret)).toEqual(["dpop.nonce.secret"]);
			if (secret) expect(String((refused as BootRefused).message), secret).not.toContain(secret);
		}
		await expect(boot({ nonce: { required: "never" } })).resolves.toBeDefined();
	});
});

it("warns at every start where no nonce is asked, and not where one is", async () => {
	const warned = async (nonce: Record<string, unknown>) => {
		const recorded = recordingLog();
		await assemble({ ...assembly({ nonce }), runtime: quietRuntime({ log: recorded.log }) });
		return recorded.lines().filter((line) => line.event === "dpop.nonce_not_asked");
	};
	expect(await warned({ required: "never" })).toEqual([
		{
			level: "warn",
			event: "dpop.nonce_not_asked",
			fields: { reason: "no nonce is asked, so a proof made ahead is taken within its window" },
		},
	]);
	const secret = randomBytes(32).toString("base64");
	expect(await warned({ required: "as", secret })).toEqual([]);
});

it("takes all it names, asking nonces or not", async () => {
	const nonce = { required: "as", ttl: "300s", secret: randomBytes(32).toString("base64") };
	for (const section of [undefined, { nonce }]) {
		// Its own entry alone: another module's takes this composition leaves unused are its owner's to check.
		expect((await takesUnused(assembly(section)))["dpop"], JSON.stringify(section)).toBeUndefined();
	}
});
