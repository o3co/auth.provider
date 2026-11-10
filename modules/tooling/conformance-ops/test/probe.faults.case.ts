import { generateKeyPairSync } from "node:crypto";
import { Agent, get } from "node:http";
import { type AreaScene, areaTarget, sceneOf } from "@mod/conformance";
import {
	type Deployed,
	type Instance,
	instanceOf,
	type Match,
	on,
	ready,
	successes,
} from "@mod/conformance/testing";
import { oauthScene } from "@mod/conformance-oauth";
import { describe, expect, it } from "vitest";
import { opsArea } from "../src/area.ts";

const pair = generateKeyPairSync("ed25519");
const oauth = oauthScene({
	issuer: "https://issuer.example",
	keys: {
		signing: {
			kid: "probe",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	clients: [
		{
			id: "app",
			kind: "confidential",
			method: "client_secret_post",
			secret: "app-secret-0123456789abcdef",
			grants: ["client_credentials"],
			scopes: ["read"],
		},
	],
});
/** What a deployment keeping a space that must not be evicted answers, on the Redis store. */
const scene: AreaScene = {
	...oauth,
	parts: { ...oauth.parts, ...sceneOf(opsArea.part({})).parts },
	storeFaults: true,
};

const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
/** One Redis command, by its name and where it holds them, its arguments. */
const command = (name: string, ...args: readonly string[]): Match => ({
	request: (asked) =>
		asked.name === name && args.every((arg, i) => asked.args[i]?.toString("latin1") === arg),
	succeeded: () => true,
});
/** A set of the boot check's commands reads this setting once, and nothing else reads it. */
const checks = (i: Instance) => successes(i, command("CONFIG", "GET", "maxmemory-policy")).length;
const pings = (i: Instance) => successes(i, command("PING")).length;
const statusOf = async (url: string) => {
	const answer = await fetch(url);
	await answer.arrayBuffer();
	return answer.status;
};

/** Sends `ask` so many times a second for `seconds`, answering how long it took and every status. */
async function paced(perSecond: number, seconds: number, ask: () => Promise<number>) {
	const began = performance.now();
	const answers: Promise<number>[] = [];
	for (let n = 0; n < perSecond * seconds; n++) {
		await pause(Math.max(0, began + (n * 1000) / perSecond - performance.now()));
		answers.push(ask());
	}
	const statuses = await Promise.all(answers);
	return { statuses, elapsedMs: performance.now() - began };
}

/** Runs a scene on a deployment of one instance on a Redis of its own, without replicas. */
const onOne = (name: string, scene_: (d: Deployed, i: Instance) => Promise<void>) =>
	on({ name, scene, replicas: 0 }, (d) => scene_(d, instanceOf(d)));

describe("what a readiness probe and a scrape cost the store", () => {
	it("runs about one set of checks a second at 50 requests a second, every answer 200", async () => {
		await onOne("ops-probe-rate", async (_, i) => {
			const [checksBefore, pingsBefore] = [checks(i), pings(i)];
			const { statuses, elapsedMs } = await paced(50, 5, () => statusOf(`${i.baseUrl}/readyz`));
			expect(new Set(statuses)).toEqual(new Set([200]));
			const run = checks(i) - checksBefore;
			expect(run).toBeGreaterThanOrEqual(3);
			expect(run).toBeLessThanOrEqual(Math.ceil(elapsedMs / 1000) + 1);
			// Every run still PINGs: far more of them than of the checks.
			expect(pings(i) - pingsBefore).toBeGreaterThan(run * 5);
		});
	});

	it("holds a scrape and a probe to the one cap between them", async () => {
		await onOne("ops-probe-scrape", async (_, i) => {
			const before = checks(i);
			const at = [`${i.baseUrl}/readyz`, `${i.baseUrl}/metrics`];
			let turn = 0;
			const { statuses, elapsedMs } = await paced(40, 4, () =>
				statusOf(at[turn++ % at.length] as string),
			);
			expect(new Set(statuses)).toEqual(new Set([200]));
			const run = checks(i) - before;
			expect(run).toBeGreaterThanOrEqual(2);
			expect(run).toBeLessThanOrEqual(Math.ceil(elapsedMs / 1000) + 1);
		});
	});
});

describe("how soon a probe shows a change of the store", () => {
	it("is unready at the next probe after a ready answer once the store stops, within the second's checks", async () => {
		await onOne("ops-probe-stopped", async (d, i) => {
			const node = d.topology.primary();
			expect(await statusOf(`${i.baseUrl}/readyz`)).toBe(200);
			d.topology.pause(node, true);
			try {
				expect(await statusOf(`${i.baseUrl}/readyz`)).toBe(503);
			} finally {
				d.topology.pause(node, false);
			}
			await ready(i);
		});
	});

	it("shows a changed maxmemory-policy unready within 2 s, and clears once it is back", async () => {
		await onOne("ops-probe-policy", async (d, i) => {
			const node = d.topology.primary();
			expect(await statusOf(`${i.baseUrl}/readyz`)).toBe(200);
			await node.ask("CONFIG", "SET", "maxmemory-policy", "allkeys-lru");
			const changed = performance.now();
			let status = 200;
			while (status === 200 && performance.now() - changed < 2000) {
				status = await statusOf(`${i.baseUrl}/readyz`);
				if (status === 200) await pause(25);
			}
			expect(status).toBe(503);
			await node.ask("CONFIG", "SET", "maxmemory-policy", "noeviction");
			await ready(i, 5000);
		});
	});

	it("never answers ready once a stop has begun, on a connection kept alive", async () => {
		const target = await areaTarget().start(scene);
		if (target.kind !== "running") throw new Error(`refused:\n${target.output}`);
		const agent = new Agent({ keepAlive: true, maxSockets: 1 });
		const answers: { sentAt: number; status: number; reused: boolean }[] = [];
		/** One probe on the kept connection; 0 where the connection fails, as a stop's end does. */
		const probe = () =>
			new Promise<(typeof answers)[number]>((resolve) => {
				const sentAt = performance.now();
				const request = get(`${target.baseUrl}/readyz`, { agent }, (answer) => {
					answer.resume();
					answer.on("end", () =>
						resolve({ sentAt, status: answer.statusCode ?? 0, reused: request.reusedSocket }),
					);
				});
				request.on("error", () => resolve({ sentAt, status: 0, reused: false }));
			});
		let stopped = false;
		const probing = (async () => {
			while (!stopped) {
				answers.push(await probe());
				await pause(5);
			}
		})();
		try {
			while (answers.length < 5) await pause(10);
			expect(answers.map((a) => a.status)).toContain(200);
			expect(answers.some((a) => a.reused)).toBe(true);
		} finally {
			const stopping = performance.now();
			await target.stop();
			stopped = true;
			await probing;
			agent.destroy();
			// A probe already at the process as the signal came may still be read ready.
			const late = answers.filter((a) => a.sentAt > stopping + 500);
			expect(late.filter((a) => a.status === 200)).toEqual([]);
			const firstOther = answers.findIndex((a) => a.status !== 200);
			expect(firstOther).toBeGreaterThan(0);
			expect(answers.slice(firstOther).filter((a) => a.status === 200)).toEqual([]);
		}
	});
});
