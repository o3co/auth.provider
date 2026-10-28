import type { AreaScene } from "../areas.ts";
import { type Instance, startDeployment } from "../deployment/deployment.ts";
import { startTopology, type Topology } from "../faults/topology.ts";
import type { Match, Upstream } from "../relay/relay.ts";

/** What every node of a topology with replicas starts with: a write needs one replica, lagging no more than 2 s. */
const replicated = ["--min-replicas-to-write", "1", "--min-replicas-max-lag", "2"];
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export interface Deployed {
	readonly topology: Topology;
	readonly instances: readonly Instance[];
	stop(): Promise<void>;
}

export interface Deploying {
	readonly name: string;
	readonly scene: AreaScene;
	/** 2 unless said otherwise. */
	readonly replicas?: number;
	/** 1 unless said otherwise. */
	readonly instances?: number;
	/** Settings every node starts with, after the replication's. */
	readonly settings?: readonly string[];
	/** Keys of the Redis section beside its URL. */
	readonly redis?: Readonly<Record<string, unknown>>;
	/** A libfaketime offset every Redis node's clock runs at, such as `+2h`. */
	readonly clock?: string;
}

/** A scene deployed on a topology of its own, its instances each behind a relay. */
export async function deployed(o: Deploying): Promise<Deployed> {
	const replicas = o.replicas ?? 2;
	const topology = await startTopology({
		replicas,
		settings: [...(replicas > 0 ? replicated : []), ...(o.settings ?? [])],
		...(o.clock ? { clock: o.clock } : {}),
	});
	try {
		const deployment = await startDeployment({
			name: o.name,
			scene: o.scene,
			topology,
			instances: o.instances ?? 1,
			...(o.redis ? { redis: o.redis } : {}),
		});
		return {
			topology,
			instances: deployment.instances,
			async stop() {
				try {
					await deployment.stop();
				} finally {
					await topology.stop();
				}
			},
		};
	} catch (error) {
		await topology.stop();
		throw error;
	}
}

/** Runs a scene on a deployment of its own, stopped however the scene ends. */
export async function on(o: Deploying, scene: (d: Deployed) => Promise<void>) {
	const d = await deployed(o);
	try {
		await scene(d);
	} finally {
		await d.stop();
	}
}

/** The instance at `index`, which the scene's deployment must have. */
export const instanceOf = (d: Deployed, index = 0): Instance => {
	const i = d.instances[index];
	if (!i) throw new Error(`the deployment has no instance ${index}`);
	return i;
};

/** The successful executions the instance's relay saw of a match. */
export const successes = (i: Instance, match: Match) =>
	i.relay.executions(match).filter((e) => e.succeeded);

/** Until the instance's relay holds an open connection to `upstream`, within 10 s. */
export async function reconnected(i: Instance, upstream: Upstream) {
	const end = performance.now() + 10_000;
	const to = (c: { upstream: Upstream }) =>
		c.upstream.host === upstream.host && c.upstream.port === upstream.port;
	while (!i.relay.connections().some((c) => c.open && to(c))) {
		if (performance.now() > end) throw new Error(`instance ${i.index} did not connect again`);
		await pause(100);
	}
}

/** Until the instance answers `/readyz` ready, within 30 s, as a scene waits for a fault healed. */
export async function ready(i: Instance, ms = 30_000): Promise<void> {
	const end = performance.now() + ms;
	for (;;) {
		const left = end - performance.now();
		if (left <= 0) throw new Error(`instance ${i.index} not ready within ${ms} ms`);
		// Each request ends with the time left, so an instance that takes it and never answers holds no one.
		const status = await fetch(`${i.baseUrl}/readyz`, {
			signal: AbortSignal.timeout(Math.ceil(left)),
		}).then(
			async (r) => {
				await r.body?.cancel();
				return r.status;
			},
			() => 0,
		);
		// Ready only within the time: an answer past it is too late.
		if (status === 200 && performance.now() <= end) return;
		await pause(Math.min(200, Math.max(0, end - performance.now())));
	}
}

/**
 * Until the primary has every replica the topology names online again, within 30 s: a node started
 * again answers before its replicas are back, and a write needs one of them.
 */
export async function replicasOnline(d: Deployed): Promise<void> {
	const end = performance.now() + 30_000;
	const want = d.topology.replicas().length;
	for (;;) {
		const info = await d.topology.primary().ask("INFO", "replication");
		const text = info.kind === "bulk" ? (info.data?.toString() ?? "") : "";
		const online = text.split("\n").filter((l) => /^slave\d+:.*state=online/.test(l)).length;
		if (online >= want) return;
		if (performance.now() > end) throw new Error(`${online} of ${want} replicas online`);
		await pause(100);
	}
}

/**
 * Until the primary takes writes again, within 30 s: as many good replicas as its
 * `min-replicas-to-write` asks, as `INFO replication` counts them. A primary that slept or was held
 * answers at once, before its replicas' acknowledgements catch up, and refuses writes as
 * `NOREPLICAS` meanwhile, which an instance's readiness does not show.
 */
export async function writable(d: Deployed): Promise<void> {
	const end = performance.now() + 30_000;
	const asked = await d.topology.primary().ask("CONFIG", "GET", "min-replicas-to-write");
	const value = asked.kind === "array" ? asked.items?.[1] : undefined;
	const want = value?.kind === "bulk" ? Number(value.data?.toString() ?? 0) : 0;
	for (;;) {
		const info = await d.topology.primary().ask("INFO", "replication");
		const text = info.kind === "bulk" ? (info.data?.toString() ?? "") : "";
		const good = Number(/min_slaves_good_slaves:(\d+)/.exec(text)?.[1] ?? 0);
		if (good >= want) return;
		if (performance.now() > end) throw new Error(`${good} of ${want} good replicas to write`);
		await pause(100);
	}
}

/**
 * Until the topology has recovered from a fault, within 30 s: the primary has every replica the
 * topology names online, and as many good replicas as its `min-replicas-to-write` asks, so it takes
 * writes again, which an instance's readiness does not show. A scene calls it in its recovery alone,
 * never while it holds the primary unwritable on purpose. Past the bound it fails naming what it
 * waited on.
 */
export async function recovered(d: Deployed): Promise<void> {
	const end = performance.now() + 30_000;
	const primary = d.topology.primary();
	const asked = await primary.ask("CONFIG", "GET", "min-replicas-to-write");
	const value = asked.kind === "array" ? asked.items?.[1] : undefined;
	if (value?.kind !== "bulk") {
		throw new Error(`the primary did not answer min-replicas-to-write: ${JSON.stringify(asked)}`);
	}
	const toWrite = Number(value.data?.toString() ?? "");
	const named = d.topology.replicas().length;
	for (;;) {
		const info = await primary.ask("INFO", "replication");
		const text = info.kind === "bulk" ? (info.data?.toString() ?? "") : "";
		const online = text.split("\n").filter((l) => /^slave\d+:.*state=online/.test(l)).length;
		const good = Number(/min_slaves_good_slaves:(\d+)/.exec(text)?.[1] ?? 0);
		if (online >= named && good >= toWrite) return;
		if (performance.now() > end) {
			throw new Error(
				`not recovered within 30 s: ${online} of ${named} replicas online, min_slaves_good_slaves ${good} of the ${toWrite} min-replicas-to-write asks`,
			);
		}
		await pause(100);
	}
}

/** Points every instance's relay at the primary where it answers now, as a crash may move it. */
export function repointed(d: Deployed): void {
	for (const i of d.instances) {
		i.relay.switchUpstream(d.topology.primary().upstream());
		i.relay.reset("all");
	}
}

/**
 * Promotes a replica that has caught up, as `promotion` checks, killing the old primary and
 * reattaching the other replicas, then points every instance's relay at the new primary.
 */
export async function failover(d: Deployed): Promise<void> {
	const [next, ...others] = d.topology.replicas();
	if (!next) throw new Error("no replica to promote");
	await d.topology.promote({ replica: next, reattach: others });
	repointed(d);
	await replicasOnline(d);
}
