import { execFileSync } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { generate, type Plan, trialSettings } from "@mod/create-app";
import type { AreaScene, NewPart, Party } from "../areas.ts";
import { auditSink } from "../audit/audit.ts";
import { baseEnv, freePort, launch, type Started, startRedis } from "../driver.ts";
import { fakeSmtp } from "../smtp.ts";

export const workspace = dirname(
	execFileSync("pnpm", ["root", "-w"], { cwd: import.meta.dirname, encoding: "utf8" }).trim(),
);

/** The store each mark composes: one that can be paused, or one that can lose data. */
export const stores = { pausable: "@mod/redis", volatile: "@mod/store" } as const;
export type StoreKind = keyof typeof stores;

const apps = new Map<string, Promise<string>>();

/** One generated application per plan, shared by the scenes that compose the same. */
export function generated(key: string, plan: (target: string) => Plan): Promise<string> {
	let app = apps.get(key);
	if (!app) {
		app = (async () => {
			const dir = await mkdtemp(join(tmpdir(), "conformance-new-"));
			await generate(plan(dir));
			execFileSync("pnpm", ["install", "--silent"], { cwd: dir });
			return dir;
		})();
		apps.set(key, app);
	}
	return app;
}

export type Sections = Record<string, Record<string, unknown>>;

/** The parts' sections merged, over their fallbacks unless `fallback` is false. */
export function sectionsOf(parts: readonly NewPart[], fallback = true): Sections {
	const config: Sections = {};
	const sources = [
		...(fallback ? parts.map((p) => p.fallback) : []),
		...parts.map((p) => p.config),
	];
	for (const source of sources) {
		for (const [section, settings] of Object.entries(source ?? {})) {
			config[section] = { ...config[section], ...settings };
		}
	}
	return config;
}

/**
 * Starts the generated app at `dir` on the scene's sections, its audit sink and its store. With
 * `trial`, `create-app`'s trial settings fill the keys the scene leaves unset, except in the sections
 * it leaves: its environment, and its local layer between the scene and the generated configuration.
 * With `trial.smtp`, a fake relay takes the app's mail.
 */
export async function started(
	dir: string,
	config: Sections,
	scene: AreaScene,
	store: StoreKind | undefined,
	trial?: {
		readonly leave: readonly string[];
		readonly parties?: readonly Party[];
		readonly smtp?: boolean;
	},
): Promise<Started> {
	const parties = trial?.parties ?? [];
	const stopParties = () => Promise.all(parties.map((p) => p.stop()));
	const port = await freePort();
	const sink = await auditSink();
	const smtp = trial?.smtp ? await fakeSmtp() : undefined;
	// The settings the Redis store requires of a server before it starts.
	const redis =
		store === "pausable"
			? await startRedis([
					"--maxmemory-policy",
					"noeviction",
					"--appendonly",
					"yes",
					"--appendfsync",
					"always",
				])
			: undefined;
	const { outbound: given, ...sections } = config;
	const { allow, "plain-loopback": loopback, ...outbound } = given ?? {};
	const reached = [new URL(sink.url), ...parties.map((p) => new URL(p.base))];
	const reach = {
		allow: [...((allow as string[]) ?? []), ...reached.map((at) => at.hostname)],
		plainLoopback: [...((loopback as string[]) ?? []), ...reached.map((at) => at.host)],
	};
	// Lists replace each other across layers, so the trial's outbound block takes every host.
	const trialLists = trial !== undefined && !trial.leave.includes("outbound");
	const lists = trialLists ? {} : { allow: reach.allow, "plain-loopback": reach.plainLoopback };
	const settings = {
		...sections,
		http: { ...config.http, port },
		audit: { receivers: ["http"] },
		"audit-http": { url: sink.url },
		...(trialLists && Object.keys(outbound).length === 0
			? {}
			: { outbound: { ...outbound, ...lists } }),
		...(store === "volatile"
			? { store: { "accept-volatile": scene.acceptVolatileStore ?? true } }
			: {}),
		...(redis ? { redis: { url: redis.url, replication: "none" } } : {}),
		...(smtp ? { "mail-smtp": { host: smtp.host, port: smtp.port, security: "none" } } : {}),
	};
	const scratch = await mkdtemp(join(tmpdir(), "conformance-scene-"));
	const file = join(scratch, "scene.conf");
	await writeFile(file, JSON.stringify(settings));
	const layers = [file];
	let env: Record<string, string> = {};
	if (trial) {
		// No Redis in the scene leaves the trial's URL unread: the app composes no Redis store.
		const given = await trialSettings(dir, {
			redisUrl: redis?.url ?? "redis://127.0.0.1:1",
			port,
			leave: trial.leave,
			...(trialLists ? reach : {}),
		});
		const local = join(scratch, "local.conf");
		await writeFile(local, given.local);
		layers.push(local);
		env = given.env;
	}
	const running = await launch({
		command: process.execPath,
		args: ["src/main.ts"],
		cwd: dir,
		env: { ...env, ...baseEnv(), APP_CONFIG: [...layers, "config/application.conf"].join(",") },
		port,
	});
	if (running.kind !== "running") {
		await redis?.stop();
		await sink.stop();
		await smtp?.stop();
		await stopParties();
		return running;
	}
	return {
		...running,
		stop: async () => {
			await running.stop();
			await redis?.stop();
			await sink.stop();
			await smtp?.stop();
			await stopParties();
		},
		audit: sink.trail,
		...(smtp ? { mail: smtp } : {}),
		...(redis ? { fault: redis.pause } : {}),
	};
}
