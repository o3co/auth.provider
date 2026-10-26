import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { AreaScene } from "../areas.ts";
import { appClockEnv, hostLibfaketime } from "../clock/clock.ts";
import type { Started } from "../driver.ts";
import { generated, started, workspace } from "../drivers/app.ts";
import { composition } from "../drivers/composed.ts";
import { redisImage, type Topology } from "../faults/topology.ts";
import { type Relay, startRelay } from "../relay/relay.ts";
import { roleOf } from "../store-wire/store-wire.ts";
import { type Identity, identityDifferences, identityOf } from "./identity.ts";
import { markInstance, sweepStrayInstances, unmarkInstance } from "./stray.ts";
import { startTrace, type Traced } from "./trace.ts";

export interface DeploymentSpec {
	/** The scene's name, for its record. */
	readonly name: string;
	readonly scene: AreaScene;
	readonly topology: Topology;
	readonly instances: number;
	/** Keys of the Redis section beside its URL and replication, such as `command-timeout`. */
	readonly redis?: Readonly<Record<string, unknown>>;
	/** Where the scene's record is written; `CONFORMANCE_FAULTS_DIR` by default, else nowhere. */
	readonly recordTo?: string;
}

/** What a scene ran on, written beside the run's reports. */
export interface DeploymentRecord {
	readonly name: string;
	readonly image: string;
	readonly replicas: number;
	readonly instances: number;
	/** The kernel's `deployment`: `multi` wherever more than one instance runs. */
	readonly deployment: unknown;
	readonly relays: true;
	/** The Redis section every instance had, its URL (each instance's relay) left out. */
	readonly redis: Readonly<Record<string, unknown>>;
	/** A hash of the settings each instance was started from, in order. */
	readonly settings: readonly string[];
	/** The issuer and key ids every instance publishes alike, checked before the scene runs; none where none publishes. */
	readonly identity: Identity;
	/** Each instance's clock offset, in order: none for the real clock. */
	readonly clocks: readonly (string | null)[];
	readonly commit: string | null;
	readonly run: string | null;
}

export interface Instance {
	readonly index: number;
	/** Its trace's URL: the same across a restart. */
	readonly baseUrl: string;
	readonly relay: Relay;
	requests(): readonly Traced[];
	running(): boolean;
	/** Ends it with SIGKILL, what it started with it, answering when it ended on the relay's clock. */
	kill(): Promise<{ readonly signal: string | null; readonly endedAt: number }>;
	/** Starts it again from the same settings, behind the same URL and relay, on the clock it had. */
	restart(): Promise<void>;
	/**
	 * Starts it again on a clock moved by `offset` (`+2h`, `-30m`), its monotonic clock left alone, by
	 * libfaketime; refused where this host has no thread-safe libfaketime (Linux, glibc).
	 */
	clock(offset: string): Promise<void>;
}

/**
 * A scene's app as a deployment runs it: several instances from one generated app and one settings
 * object, on one Redis topology, each behind a relay and a trace of its own.
 */
export async function startDeployment(spec: DeploymentSpec) {
	// Instances a run that ended abruptly left behind would answer on ports and hold Redis connections.
	await sweepStrayInstances();
	const { modules, config, layers, store } = composition(spec.scene);
	if (store !== "pausable") throw new Error("a fault scene runs on the Redis store");
	const kernel: Record<string, unknown> =
		spec.instances > 1 ? { ...config.kernel, deployment: "multi" } : { ...config.kernel };
	const settings = { ...config, kernel };
	const dir = await generated(modules.join(","), (target) => ({ target, modules, workspace }));
	const replication = spec.topology.replicas().length > 0 ? "replicas" : "none";
	const redis = { replication, ...spec.redis };
	const hash = createHash("sha256")
		.update(JSON.stringify({ modules, settings, layers, redis }))
		.digest("hex");
	const instances: Instance[] = [];
	let identity: Identity = null;
	let record: DeploymentRecord | undefined;
	/** The record, written again as a clock moves; nowhere without a place for it. */
	const written = async () => {
		const to = spec.recordTo ?? process.env.CONFORMANCE_FAULTS_DIR;
		if (!to || !record) return;
		await mkdir(to, { recursive: true });
		await writeFile(join(to, `${spec.name.replace(/[^\w.-]/g, "_")}.json`), JSON.stringify(record));
	};
	const clocks: (string | null)[] = [];
	const currents: { baseUrl: string }[] = [];
	const stops: (() => Promise<void>)[] = [];
	const stopAll = async () => {
		const failures: string[] = [];
		for (const stop of stops.reverse()) {
			await stop().catch((error: unknown) => {
				failures.push(error instanceof Error ? error.message : String(error));
			});
		}
		if (failures.length > 0) throw new Error(`the deployment failed:\n${failures.join("\n")}`);
	};
	try {
		for (let index = 0; index < spec.instances; index++) {
			const relay = await startRelay({ upstream: spec.topology.primary().upstream(), roleOf });
			stops.push(() => relay.close());
			clocks.push(null);
			const start = async () => {
				const offset = clocks[index];
				const library = hostLibfaketime();
				const env = offset && library ? appClockEnv(offset, library) : undefined;
				const s = await started(
					dir,
					settings,
					spec.scene,
					store,
					undefined,
					layers,
					{},
					{
						redis: { url: relay.url, ...redis },
						...(env ? { env } : {}),
					},
				);
				if (s.kind !== "running") throw new Error(`instance ${index} refused:\n${s.output}`);
				if (s.pid) await markInstance(s.pid);
				currents[index] = s;
				return s;
			};
			const ending = async () => {
				const pid = current.pid;
				await current.stop();
				if (pid) await unmarkInstance(pid);
			};
			let current: Extract<Started, { kind: "running" }> = await start();
			let alive = true;
			const trace = await startTrace(current.baseUrl);
			stops.push(() => trace.stop());
			// Stopped after a kill too: the instance's audit sink and parties go with it.
			stops.push(() => ending());
			instances.push({
				index,
				baseUrl: trace.url,
				relay,
				requests: () => trace.requests(),
				running: () => alive,
				async kill() {
					if (!current.kill) throw new Error("the instance was not launched as a group");
					const ended = await current.kill();
					if (current.pid) await unmarkInstance(current.pid);
					alive = false;
					return ended;
				},
				async restart() {
					await ending();
					current = await start();
					alive = true;
					trace.pointAt(current.baseUrl);
				},
				async clock(offset) {
					if (!hostLibfaketime())
						throw new Error(
							"moving an instance's clock needs the thread-safe libfaketime of glibc Linux (CONFORMANCE_FAKETIME_LIB to name it)",
						);
					clocks[index] = offset;
					await ending();
					current = await start();
					alive = true;
					trace.pointAt(current.baseUrl);
					await written();
				},
			});
		}
		// One deployment, as a scene takes it: every instance names the same issuer and keys.
		const identities = await Promise.all(currents.map((c) => identityOf(c.baseUrl)));
		const differences = identityDifferences(identities);
		if (differences.length > 0)
			throw new Error(`the instances are not one deployment:\n${differences.join("\n")}`);
		identity = identities[0] ?? null;
	} catch (error) {
		await stopAll().catch(() => undefined);
		throw error;
	}
	record = {
		name: spec.name,
		image: redisImage,
		replicas: spec.topology.replicas().length,
		instances: spec.instances,
		deployment: kernel.deployment,
		relays: true,
		redis,
		settings: instances.map(() => hash),
		identity,
		clocks,
		commit: process.env.GITHUB_SHA ?? null,
		run: process.env.GITHUB_RUN_ID ?? null,
	};
	await written();
	return { instances, record: record as DeploymentRecord, stop: stopAll };
}

export type Deployment = Awaited<ReturnType<typeof startDeployment>>;
