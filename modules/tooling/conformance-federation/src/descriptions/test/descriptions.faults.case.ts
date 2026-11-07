import { generateKeyPairSync, randomBytes } from "node:crypto";
import { connect } from "node:net";
import type { AreaScene } from "@mod/conformance";
import {
	type Instance,
	startDeployment,
	startTopology,
	type Topology,
} from "@mod/conformance/testing";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { browser as openBrowser, probeClient } from "../../../test/browser.ts";
import { fakeUpstream } from "../../../test/upstream.ts";
import { upstreamClient } from "../../grants/test/grants.ts";
import { type FederationScene, federationScene, landedStatus } from "../../main.ts";

const origin = "https://issuer.example";
const landing = "https://app.example/home";
const password = "correct horse battery";
const pair = generateKeyPairSync("ed25519");
const keys = {
	signing: {
		kid: "descriptions",
		alg: "EdDSA" as const,
		privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
		publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
	},
};
const start = (idp: string) => `/session/oauth/federation/${idp}`;
/**
 * A port no test takes: `listen(0)` picks from the ephemeral range, never port 2. Not port 1, as
 * elsewhere: outbound never reaches the ports the Fetch standard calls bad, port 1 among them.
 */
const refusedPort = 2;
/** An issuer nothing answers at: every connection to it is refused. */
const refusedIssuer = `http://127.0.0.1:${refusedPort}`;

beforeAll(async () => {
	const answer = await new Promise<string>((resolve) => {
		const socket = connect(refusedPort, "127.0.0.1");
		socket.once("connect", () => {
			socket.destroy();
			resolve("connected");
		});
		socket.once("error", (error: NodeJS.ErrnoException) => resolve(error.code ?? "error"));
	});
	if (answer !== "ECONNREFUSED") {
		throw new Error(
			`127.0.0.1:${refusedPort} must refuse connections for these scenes (got ${answer})`,
		);
	}
});

type Upstream = Awaited<ReturnType<typeof fakeUpstream>>;

/** What a scene started and stops however it ends. */
const stops: (() => Promise<unknown>)[] = [];
afterEach(async () => {
	for (const stop of stops.splice(0).reverse()) await stop();
});

async function aStore(): Promise<Topology> {
	const topology = await startTopology({ replicas: 0 });
	stops.push(() => topology.stop());
	return topology;
}
async function anUpstream(): Promise<Upstream> {
	const upstream = await fakeUpstream(upstreamClient);
	stops.push(() => upstream.stop());
	return upstream;
}

/** Starts the scene, on the Redis store, as the deployment's one instance; its stop is the scene's. */
async function started(topology: Topology, scene: AreaScene) {
	const deployment = await startDeployment({
		name: `descriptions-${randomBytes(4).toString("hex")}`,
		scene: { ...scene, storeFaults: true },
		topology,
		instances: 1,
	});
	return { instance: deployment.instances[0] as Instance, stop: () => deployment.stop() };
}

const idp = (name: string, issuer: string): FederationScene["idps"][number] => ({
	name,
	issuer,
	clientId: upstreamClient.id,
	clientSecret: upstreamClient.secret,
});

/** A deployment logging alice in through `corp`, beside the other IdPs given. */
const withIdps = (idps: FederationScene["idps"]): AreaScene =>
	federationScene({
		origin,
		keys,
		idps,
		landing,
		returnTargets: [],
		users: [{ identifier: "alice", password, upstream: { idp: "corp", subject: "u-alice" } }],
		clients: [probeClient],
	});

/** How a fresh browser's start through the IdP is answered. */
async function startStatus(i: Instance, name: string) {
	return (await openBrowser(() => i.baseUrl, origin).get(start(name))).status;
}

/** Whom a fresh browser logging in through the IdP as `subject` is logged in as, or the status it is refused with. */
async function federatedAs(i: Instance, upstream: Upstream, name: string, subject: string) {
	const b = openBrowser(() => i.baseUrl, origin);
	const begun = await b.get(start(name));
	if (begun.status === 503) return 503;
	const back = await b.get(
		`${start(name)}/callback?${upstream.authorize(begun.location, { subject })}`,
	);
	return back.status === landedStatus() ? await b.loggedInAs() : back.status;
}

/** The instance's lines about an IdP's description, as `event idp failure`. */
const toldOfDescriptions = (i: Instance) =>
	i
		.output()
		.split("\n")
		.filter((line) => line.includes("idp-oidc.description_"))
		.map((line) => {
			const { event, idp, failure } = JSON.parse(line) as Record<string, string>;
			return [event, idp, failure].filter(Boolean).join(" ");
		});

describe("an OpenID Connect IdP whose description cannot be read at boot", () => {
	it("boots, the IdP alone unavailable, where its issuer refuses the connection or answers 429; the other IdP logs in", async () => {
		const [topology, corp, busy] = [await aStore(), await anUpstream(), await anUpstream()];
		busy.describing(429);
		const { instance, stop } = await started(
			topology,
			withIdps([idp("corp", corp.issuer), idp("down", refusedIssuer), idp("busy", busy.issuer)]),
		);
		stops.push(stop);
		expect(toldOfDescriptions(instance)).toEqual([
			"idp-oidc.description_unavailable down unreachable",
			"idp-oidc.description_unavailable busy status-429",
		]);
		expect(await startStatus(instance, "down")).toBe(503);
		expect(await startStatus(instance, "busy")).toBe(503);
		expect(typeof (await federatedAs(instance, corp, "corp", "u-alice"))).toBe("string");
	});

	it("reads it again once needed a minute on, the first start after it answers 503 and the next logging in", async () => {
		const [topology, corp] = [await aStore(), await anUpstream()];
		corp.describing(503);
		const { instance, stop } = await started(topology, withIdps([idp("corp", corp.issuer)]));
		stops.push(stop);
		expect(await startStatus(instance, "corp")).toBe(503);
		corp.describing("itself");
		// The minute is waited in real time: moving an instance's clock restarts it, and a restart
		// would read the description at boot, not again.
		await new Promise((resolve) => setTimeout(resolve, 61_000));
		// The first start begins the read and answers at once, unavailable.
		expect(await startStatus(instance, "corp")).toBe(503);
		let status = 503;
		for (let tries = 0; status === 503 && tries < 50; tries++) {
			await new Promise((resolve) => setTimeout(resolve, 200));
			status = await startStatus(instance, "corp");
		}
		expect(status).not.toBe(503);
		expect(typeof (await federatedAs(instance, corp, "corp", "u-alice"))).toBe("string");
		expect(toldOfDescriptions(instance)).toEqual([
			"idp-oidc.description_unavailable corp status-5xx",
			"idp-oidc.description_read corp",
		]);
	});

	it("still refuses boot where the description answers naming another issuer", async () => {
		const [topology, corp] = [await aStore(), await anUpstream()];
		corp.describing({ issuer: "https://elsewhere.example" });
		const said = await started(topology, withIdps([idp("corp", corp.issuer)])).then(
			async ({ stop }) => {
				await stop();
				return "booted";
			},
			(error: unknown) => String(error),
		);
		expect(said).toContain("the description names another issuer");
	});
});
