import { generateKeyPairSync, randomBytes } from "node:crypto";
import { type AreaScene, fakeHttp, sceneOf } from "@mod/conformance";
import {
	type Instance,
	startDeployment,
	startTopology,
	type Topology,
} from "@mod/conformance/testing";
import { identityArea } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { oauthArea } from "@mod/conformance-oauth";
import { afterEach, describe, expect, it } from "vitest";
import { browser as openBrowser, probeClient } from "../../../test/browser.ts";
import { fakeUpstream } from "../../../test/upstream.ts";
import { grantsAt, grantsScene, scopes, upstreamClient } from "../../grants/test/grants.ts";
import { type FederationScene, federationScene, landedStatus } from "../../main.ts";

const origin = "https://issuer.example";
const landing = "https://app.example/home";
const password = "correct horse battery";
const pair = generateKeyPairSync("ed25519");
const keys = {
	signing: {
		kid: "names",
		alg: "EdDSA" as const,
		privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
		publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
	},
};
const start = (idp: string) => `/session/oauth/federation/${idp}`;

const upstreamAt = () => fakeUpstream(upstreamClient);
type Upstream = Awaited<ReturnType<typeof upstreamAt>>;

/** What a scene started and stops however it ends. */
const stops: (() => Promise<unknown>)[] = [];
afterEach(async () => {
	for (const stop of stops.splice(0).reverse()) await stop();
});

/** One Redis, kept from one start of a scene to the next. */
async function aStore(): Promise<Topology> {
	const topology = await startTopology({ replicas: 0 });
	stops.push(() => topology.stop());
	return topology;
}
async function anUpstream(): Promise<Upstream> {
	const upstream = await upstreamAt();
	stops.push(() => upstream.stop());
	return upstream;
}

/** The scene on the Redis store, as a start of a deployment takes it. */
const onRedis = (scene: AreaScene): AreaScene => ({ ...scene, storeFaults: true });

/** Starts the scene as the deployment's one instance, and answers it; its stop is the scene's to call. */
async function started(topology: Topology, scene: AreaScene) {
	const deployment = await startDeployment({
		name: `names-${randomBytes(4).toString("hex")}`,
		scene: onRedis(scene),
		topology,
		instances: 1,
	});
	const instance = deployment.instances[0] as Instance;
	return { instance, stop: () => deployment.stop() };
}

/** Starts it and stops it again, what it kept staying in the store. */
async function startedOnce(topology: Topology, scene: AreaScene) {
	const { stop } = await started(topology, scene);
	await stop();
}

/** What the instance refused with, failing the scene where it boots. */
async function refusedWith(topology: Topology, scene: AreaScene): Promise<string> {
	const answer = await started(topology, scene).then(
		async ({ stop }) => {
			await stop();
			return undefined;
		},
		(error: unknown) => String(error),
	);
	if (answer === undefined) throw new Error("the deployment booted");
	return answer;
}

const corpIdp = (issuer: string, name = "corp"): FederationScene["idps"][number] => ({
	name,
	issuer,
	clientId: upstreamClient.id,
	clientSecret: upstreamClient.secret,
});

/** A deployment logging alice in through the name, her link in the settings where it is told. */
const named = (idps: FederationScene["idps"], more: Partial<FederationScene> = {}): AreaScene =>
	federationScene({
		origin,
		keys,
		idps,
		landing,
		returnTargets: [],
		users: [{ identifier: "alice", password, upstream: { idp: "corp", subject: "u-alice" } }],
		clients: [probeClient],
		...more,
	});

/** Whom a fresh browser logging in through the name as `subject` is logged in as, or the status it is refused with. */
async function federatedAs(i: Instance, upstream: Upstream, idp: string, subject: string) {
	const b = openBrowser(() => i.baseUrl, origin);
	const begun = await b.get(start(idp));
	const back = await b.get(
		`${start(idp)}/callback?${upstream.authorize(begun.location, { subject })}`,
	);
	return back.status === landedStatus() ? await b.loggedInAs() : back.status;
}

/** The lines the instance wrote about an IdP's issuer moving or differing. */
const warnedOfNames = (i: Instance) =>
	i
		.output()
		.split("\n")
		.filter((line) => line.includes("users."));

describe("an IdP name's issuer across starts", () => {
	it("refuses boot where it changed, telling no issuer and which name", async () => {
		const [topology, a, b] = [await aStore(), await anUpstream(), await anUpstream()];
		await startedOnce(topology, named([corpIdp(a.issuer)]));
		const said = await refusedWith(topology, named([corpIdp(b.issuer)]));
		expect(said).toContain("an IdP name stands for another issuer");
		expect(said).toContain("federation");
		expect(said).not.toContain(a.issuer);
		expect(said).not.toContain(b.issuer);
	});

	it("boots again on an unchanged one with no warning, its link still reached", async () => {
		const [topology, a] = [await aStore(), await anUpstream()];
		const first = await started(topology, named([corpIdp(a.issuer)]));
		const alice = await federatedAs(first.instance, a, "corp", "u-alice");
		expect(typeof alice).toBe("string");
		await first.stop();
		const second = await started(topology, named([corpIdp(a.issuer)]));
		stops.push(second.stop);
		expect(warnedOfNames(second.instance)).toEqual([]);
		expect(await federatedAs(second.instance, a, "corp", "u-alice")).toBe(alice);
	});

	it("takes a new name for another issuer, and an account there does not reach the old name's link", async () => {
		const [topology, a, b] = [await aStore(), await anUpstream(), await anUpstream()];
		const unlinked = { users: [{ identifier: "alice", password }], links: true };
		const first = await started(topology, named([corpIdp(a.issuer)], unlinked));
		const alice = openBrowser(() => first.instance.baseUrl, origin);
		expect(
			(await alice.submit("/session/login", { username: "alice", password })).status,
		).toBeLessThan(400);
		const linking = await alice.navigate(`${start("corp")}?link=1`, {
			"sec-fetch-site": "same-origin",
		});
		await alice.get(
			`${start("corp")}/callback?${a.authorize(linking.location, { subject: "jdoe" })}`,
		);
		expect(await federatedAs(first.instance, a, "corp", "jdoe")).toBe(await alice.loggedInAs());
		await first.stop();
		const second = await started(topology, named([corpIdp(b.issuer, "corp-b")], unlinked));
		stops.push(second.stop);
		expect(await federatedAs(second.instance, b, "corp-b", "jdoe")).toBe(401);
	});

	it("takes a stated move and warns at every start while it is listed, the link going with the name", async () => {
		const [topology, a, b] = [await aStore(), await anUpstream(), await anUpstream()];
		const first = await started(topology, named([corpIdp(a.issuer)]));
		const alice = await federatedAs(first.instance, a, "corp", "u-alice");
		await first.stop();
		const moved = [{ idp: "corp", from: a.issuer, to: b.issuer }];
		for (const _start of [1, 2]) {
			const next = await started(topology, named([corpIdp(b.issuer)], { issuerMoved: moved }));
			const lines = warnedOfNames(next.instance);
			expect(lines).toHaveLength(1);
			expect(lines[0]).toContain("users.issuer_moved");
			expect(lines[0]).toContain("corp");
			expect(lines[0]).not.toContain(a.issuer);
			expect(lines[0]).not.toContain(b.issuer);
			expect(await federatedAs(next.instance, b, "corp", "u-alice")).toBe(alice);
			await next.stop();
		}
		const after = await started(topology, named([corpIdp(b.issuer)]));
		stops.push(after.stop);
		expect(warnedOfNames(after.instance)).toEqual([]);
	});

	it("refuses a move whose from does not match what is kept, at its key and telling no issuer", async () => {
		const [topology, a, b] = [await aStore(), await anUpstream(), await anUpstream()];
		await startedOnce(topology, named([corpIdp(a.issuer)]));
		const elsewhere = "https://elsewhere.example";
		const said = await refusedWith(
			topology,
			named([corpIdp(b.issuer)], { issuerMoved: [{ idp: "corp", from: elsewhere, to: b.issuer }] }),
		);
		expect(said).toContain("users.issuer-moved.0");
		for (const issuer of [a.issuer, b.issuer, elsewhere]) expect(said).not.toContain(issuer);
	});

	it("refuses boot for a ledger holding the links too, the ledger receiving no lookup", async () => {
		const [topology, a, b] = [await aStore(), await anUpstream(), await anUpstream()];
		const ledger = await fakeHttp(() => ({ status: 404, json: { error: "not_found" } }));
		stops.push(() => ledger.stop());
		const ledgered = {
			users: [],
			ledger: {
				verifyUrl: `${ledger.base}/ledger/authenticate`,
				credential: randomBytes(32).toString("hex"),
				upstreamUrl: `${ledger.base}/ledger/upstream`,
			},
			without: ["@mod/verified-email"],
		};
		await startedOnce(topology, named([corpIdp(a.issuer)], ledgered));
		const said = await refusedWith(topology, named([corpIdp(b.issuer)], ledgered));
		expect(said).toContain("an IdP name stands for another issuer");
		expect(said).not.toContain(a.issuer);
		expect(said).not.toContain(b.issuer);
		expect(ledger.received.filter((asked) => asked.path === "/ledger/upstream")).toEqual([]);
	});

	it("refuses boot where a linked JWT bearer issuer changed under one upstream, naming its module", async () => {
		const topology = await aStore();
		const ledger = await fakeHttp(() => ({ status: 404, json: { keys: [] } }));
		stops.push(() => ledger.stop());
		const linkedAt = (issuer: string) =>
			sceneOf(
				keysArea.part(keys),
				identityArea.part({
					origin,
					users: [
						{
							identifier: "alice",
							password,
							upstream: { idp: "devices", subject: "device-alice" },
						},
					],
				}),
				oauthArea.part({
					issuer: origin,
					clients: [
						{
							id: "app",
							kind: "confidential",
							method: "client_secret_post",
							secret: "app-secret-0123456789abcdef",
							grants: ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
							scopes: ["read"],
						},
					],
					jwtBearer: {
						issuers: [
							{
								issuer,
								linked: { upstream: "devices", keysUrl: `${ledger.base}/signer-keys` },
							},
						],
					},
				}),
			);
		const [before, after] = ["https://devices.example", "https://devices.other.example"];
		await startedOnce(topology, linkedAt(before));
		const said = await refusedWith(topology, linkedAt(after));
		expect(said).toContain("an IdP name stands for another issuer");
		expect(said).toContain("jwt-bearer-users");
		expect(said).not.toContain(before);
		expect(said).not.toContain(after);
	});
});

describe("a grant's refresh across starts", () => {
	const sealKey = randomBytes(32).toString("base64");
	const calendar = (idp: string) => ({
		connections: [{ name: "calendar", idp, scopes, maxAccessTokenSeconds: 3600 }],
	});
	/** A grant connected at `corp`, its token of two seconds due, past half its life. */
	const dueGrant = async (i: Instance, corp: Upstream) => {
		const { id } = await grantsAt(() => i.baseUrl, corp).connected({ expiresIn: 2 });
		await new Promise((resolve) => setTimeout(resolve, 1100));
		return id;
	};
	const refusedAtNext = async (i: Instance, corp: Upstream, id: string, reached: Upstream[]) => {
		const token = await grantsAt(() => i.baseUrl, corp).grantCall(id, "token");
		expect([token.status, token.body.error, token.body.error_description]).toEqual([
			410,
			"reauthorization_required",
			"upstream_issuer_changed",
		]);
		for (const upstream of reached) expect(upstream.refreshCalls).toEqual([]);
	};

	it("reaches no other IdP its connection comes to name, the client told reauthorization_required", async () => {
		const [topology, a, b] = [await aStore(), await anUpstream(), await anUpstream()];
		const first = await started(topology, grantsScene(a, calendar("corp"), { sealKey }));
		// The control: its token, past half its life, is refreshed at the issuer it came from.
		const refreshed = await dueGrant(first.instance, a);
		const asked = await grantsAt(() => first.instance.baseUrl, a).grantCall(refreshed, "token");
		expect(asked.status).toBe(200);
		expect(a.refreshCalls).toHaveLength(1);
		a.refreshCalls.length = 0;
		const id = await dueGrant(first.instance, a);
		await first.stop();
		const second = await started(
			topology,
			grantsScene(a, calendar("other"), {
				sealKey,
				idps: [corpIdp(a.issuer), corpIdp(b.issuer, "other")],
			}),
		);
		stops.push(second.stop);
		await refusedAtNext(second.instance, a, id, [a, b]);
	});

	it("reaches no other issuer its IdP's name is moved to", async () => {
		const [topology, a, b] = [await aStore(), await anUpstream(), await anUpstream()];
		const first = await started(topology, grantsScene(a, calendar("corp"), { sealKey }));
		const id = await dueGrant(first.instance, a);
		await first.stop();
		const second = await started(
			topology,
			grantsScene(a, calendar("corp"), {
				sealKey,
				idps: [corpIdp(b.issuer)],
				issuerMoved: [{ idp: "corp", from: a.issuer, to: b.issuer }],
			}),
		);
		stops.push(second.stop);
		await refusedAtNext(second.instance, a, id, [a, b]);
	});
});
