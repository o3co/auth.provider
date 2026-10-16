import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
	type Area,
	type AreaScene,
	auditEvents,
	baseEnv,
	freePort,
	launch,
	registerDriver,
	type Started,
	startRedis,
} from "@mod/conformance";
import { legacyDir } from "./dir.ts";

/** What the legacy build needs for one area's part. */
export interface LegacyPart {
	readonly env?: Readonly<Record<string, string>>;
	/** Lines for the build's configuration file; the parts' lines are joined. */
	readonly settings?: string;
	/** Files written to a fresh directory before the build starts; `env` may name them by `scratch`. */
	readonly files?: Readonly<Record<string, string>>;
	/**
	 * Packages the standalone build does not load, or loads in a form a scene cannot reach, which the
	 * composed entry adds: mtls, github, google, apple, webauthn, token-exchange, device-grant, dpop.
	 */
	readonly extra?: readonly string[];
}

export interface LegacySetUp<Part> {
	map(part: Part, scene: AreaScene, at: { readonly scratch: string }): LegacyPart;
	/** Needs of this area the legacy build cannot be set up for. */
	readonly cannot?: readonly string[];
	/** Decided differences of this area the legacy build answers otherwise. */
	readonly differs?: readonly string[];
}

const setUps = new Map<string, LegacySetUp<unknown>>();

/** How an area's part is set up on the legacy build; each area says it once, in its legacy file. */
export function onLegacy<Part>(owner: Area<Part>, setUp: LegacySetUp<Part>): void {
	setUps.set(owner.name, setUp as LegacySetUp<unknown>);
}

/** What the build needs whatever the scene: its port, its configuration name, in-memory stores and empty registries. */
const baseline = (port: number, scratch: string) => ({
	HTTP_PORT: String(port),
	CONFIG_ENV: "conformance",
	MFA_MODE: "off",
	OAUTH_JWT_ISSUER: "http://127.0.0.1",
	OAUTH_AUTHORIZATION_GRANTS_CLIENT_CREDENTIALS_ENABLED: "false",
	ADAPTERS_ACCESS_TOKEN_DENYLIST: "memory",
	ADAPTERS_REPLAY_SEEN_SET: "memory",
	ADAPTERS_CODE_REPOSITORY: "memory",
	SESSION_STORE_STORAGE_TYPE: "memory",
	SESSION_STORE_SECRET: randomBytes(32).toString("hex"),
	ADAPTERS_USER_REPOSITORY: "yaml",
	REPOSITORIES_USER_YAML_PATH: join(scratch, "users.yaml"),
	REPOSITORIES_CLIENT_YAML_PATH: join(scratch, "clients.yaml"),
});
/** The standalone build's entry, with the extra packages the parts ask for appended. */
const composedEntry = fileURLToPath(new URL("../scripts/composed-entry.mjs", import.meta.url));

/** The registries the baseline names, empty until a part writes its own. */
const emptyFiles = { "users.yaml": "{}\n", "clients.yaml": "{}\n" };

/** Needs no area set-up can meet: the build sends no audit events over HTTP. */
const cannotAtAll: readonly string[] = [auditEvents.need];

/** How many free ports a build is started on before its refusal stands. */
const portAttempts = 3;

/** A lock older than this is left over from a run that died while holding it. */
const lockStaleMs = 60_000;

/**
 * Holds the build's configuration directory, so runs sharing one legacy copy don't start a build on
 * another run's configuration file. Held from writing the file until the build answers.
 */
async function holdConfiguration(dir: string): Promise<() => Promise<void>> {
	const lock = join(dir, ".conformance.lock");
	for (;;) {
		try {
			await mkdir(lock);
			return () => rm(lock, { recursive: true, force: true });
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
			const held = await stat(lock).catch(() => undefined);
			if (held && Date.now() - held.mtimeMs > lockStaleMs)
				await rm(lock, { recursive: true, force: true });
			else await new Promise((resolve) => setTimeout(resolve, 50));
		}
	}
}

const legacyDriver = {
	can: (need: string) =>
		!cannotAtAll.includes(need) && ![...setUps.values()].some((s) => s.cannot?.includes(need)),
	differs: (difference: string) =>
		[...setUps.values()].some((s) => s.differs?.includes(difference)),
	async start(scene: AreaScene): Promise<Started> {
		const root = legacyDir();
		const cwd = join(root, "templates", "standalone");
		if (!existsSync(cwd)) throw new Error(`no legacy build in ${root}; run prepare-legacy first`);
		const parts = Object.entries(scene.parts).map(([name, part]) => {
			const setUp = setUps.get(name);
			if (!setUp) throw new Error(`no legacy set-up for the area ${name}`);
			return { setUp, part };
		});
		const scratch = await mkdtemp(join(tmpdir(), "conformance-legacy-"));
		const mapped = parts.map(({ setUp, part }) => setUp.map(part, scene, { scratch }));
		for (const files of [emptyFiles, ...mapped.map((m) => m.files ?? {})]) {
			for (const [name, text] of Object.entries(files)) await writeFile(join(scratch, name), text);
		}
		const faults = scene.storeFaults === true;
		// The build wires stores on Redis whatever the scene, so every scene starts one.
		const redis = await startRedis();
		const extra = [...new Set(mapped.flatMap((m) => m.extra ?? []))];
		const release = await holdConfiguration(join(cwd, "config"));
		let started: Started;
		try {
			await writeFile(
				join(cwd, "config", "conformance.conf"),
				mapped.map((m) => m.settings ?? "").join(""),
			);
			// Another run may take the free port before the build binds it; the build then exits, and a new port is tried.
			for (let attempt = 1; ; attempt++) {
				const port = await freePort();
				started = await launch({
					command: process.execPath,
					args: extra.length > 0 ? [composedEntry] : ["dist/app.mjs"],
					cwd,
					env: {
						...baseEnv(),
						...baseline(port, scratch),
						...Object.assign({}, ...mapped.map((m) => m.env ?? {})),
						REDIS_CLIENTS_URL: redis.url,
						...(extra.length > 0 ? { LEGACY_DIR: root, LEGACY_EXTRA: extra.join(",") } : {}),
					},
					port,
				});
				if (
					started.kind === "running" ||
					!started.output.includes("EADDRINUSE") ||
					attempt === portAttempts
				)
					break;
			}
		} catch (error) {
			await redis.stop();
			throw error;
		} finally {
			await release();
		}
		if (started.kind !== "running") {
			await redis.stop();
			return started;
		}
		return {
			...started,
			stop: async () => {
				await started.stop();
				await redis.stop();
			},
			...(faults ? { fault: redis.pause } : {}),
		};
	},
};

registerDriver("legacy", legacyDriver);
