import { mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { getJson } from "../api/api.ts";
import { type Command, systemCommand } from "../commands/commands.ts";
import { composeOverride, projectOf, suiteEnv } from "../compose/compose.ts";
import { reclaimOrphans } from "../orphans/orphans.ts";

/** Each command's own time: a setup step's within the plan's deadline, a stop's after it too. */
const budgetMs = {
	clone: 300_000,
	quick: 30_000,
	pip: 300_000,
	up: 600_000,
	logs: 60_000,
	down: 120_000,
} as const;

/** The suite's version, pinned: its release tag and the commit the tag names. */
export interface SuitePin {
	readonly tag: string;
	readonly commit: string;
	/** The Python packages its scripts import, each at one version. */
	readonly python: readonly string[];
}

/** The suite's public origin, as its own pages and the browser in it name it. */
export const suiteOrigin = "https://localhost.emobix.co.uk:8443";

/** How long the suite may take to answer once started: as long as its own runner waits. */
const readyWithinMs = 360_000;

/** How the suite's containers reach this machine: the name, the address the front listens on, the IPv4 the name is given where Docker gives it none. */
export interface SuiteHost {
	readonly name: string;
	readonly listen: string;
	readonly mapped?: string;
}

/** Docker Desktop names this machine itself, in IPv4; on Linux the name is given the bridge's gateway. */
export async function hostForSuite(command: Command = systemCommand): Promise<SuiteHost> {
	if (process.platform === "darwin") return { name: "host.docker.internal", listen: "127.0.0.1" };
	const { stdout } = await command(
		"docker",
		["network", "inspect", "bridge", "-f", "{{(index .IPAM.Config 0).Gateway}}"],
		{ timeoutMs: budgetMs.quick },
	);
	const gateway = stdout.trim();
	return { name: "host.docker.internal", listen: gateway, mapped: gateway };
}

/**
 * The suite's stop failed, a start's own or a stop's: what stops the suite may still be needed, so
 * whatever holds it is kept.
 */
export class SuiteStopFailed extends AggregateError {}

/** The suite at its pinned version, started in `dir`: a directory of its own, removed when it stops. */
export interface Suite {
	/** The suite's scripts, as the pinned commit holds them. */
	readonly scripts: string;
	/** The Python that runs them, with their packages. */
	readonly python: string;
	/** The certificate its nginx answers with, as PEM in a file: for the app to trust. */
	readonly certificate: string;
	/** The suite's API, as a JSON GET from this machine. */
	api(path: string): Promise<unknown>;
	stop(): Promise<void>;
}

/**
 * Starts the suite at `pin` in `dir`: its source at the pinned commit (the compose file and the
 * scripts), a Python of its own for the scripts, and its containers under a project of their own,
 * after any suite whose owner is gone was taken down. Each setup step is held to its own time and to
 * `signal`, the plan's deadline. Stopping keeps every container's state and log, stdout and stderr,
 * in `log` first, then takes the containers and their volumes down by budgets of its own, past the
 * deadline too, and removes `dir`; however the start went, but a start failing before Compose was
 * asked for a container removes `dir` alone. A stop that fails, a start's own too, is a
 * `SuiteStopFailed` telling every step that failed; where the containers were not taken down it
 * keeps `dir`, which holds what stops the suite.
 */
export async function startSuite(
	pin: SuitePin,
	dir: string,
	host: SuiteHost,
	log: string,
	/** The certificate its nginx answers with, as PEM: one naming `localhost.emobix.co.uk`. */
	tls: { readonly cert: string; readonly key: string },
	options: { readonly command?: Command; readonly signal?: AbortSignal } = {},
): Promise<Suite> {
	const command = options.command ?? systemCommand;
	const signal = options.signal;
	const source = join(dir, "suite");
	const name = projectOf(dir);
	const compose = [
		"compose",
		"-p",
		name,
		"-f",
		join(source, "docker-compose-prebuilt.yml"),
		"-f",
		join(dir, "override.yml"),
	];
	const env = suiteEnv(pin.tag, { base: suiteOrigin, mtls: "https://localhost.emobix.co.uk:8444" });
	/** A setup step: its own time, and the plan's deadline. */
	const step = (cmd: string, args: readonly string[], timeoutMs: number, cwd?: string) =>
		command(cmd, args, { timeoutMs, env, ...(signal ? { signal } : {}), ...(cwd ? { cwd } : {}) });
	const stop = async () => {
		const problems: unknown[] = [];
		/** What a command wrote, its stderr after its stdout. */
		const kept = async (args: readonly string[]) =>
			command("docker", [...compose, ...args], { timeoutMs: budgetMs.logs, env }).then(
				({ stdout, stderr = "" }) =>
					stderr === "" ? stdout : `${stdout}\n--- stderr ---\n${stderr}`,
				(error: unknown) => {
					problems.push(error);
					return "";
				},
			);
		// Every container's state and log: a failed start is often one of them gone.
		const states = await kept(["ps", "--all", "--format", "{{.Service}} {{.State}} {{.Status}}"]);
		const logs = await kept(["logs", "--no-color"]);
		await writeFile(log, `${states}\n${logs}`).catch((error: unknown) => problems.push(error));
		const down = await command("docker", [...compose, "down", "--volumes", "--remove-orphans"], {
			timeoutMs: budgetMs.down,
			env,
		}).then(
			() => true,
			(error: unknown) => {
				problems.push(error);
				return false;
			},
		);
		// What stops the suite stays while its containers may run.
		if (down)
			await rm(dir, { recursive: true, force: true }).catch((error: unknown) =>
				problems.push(error),
			);
		if (problems.length > 0)
			throw new SuiteStopFailed(
				problems,
				`the suite's stop failed${down ? "" : `; its compose files stay in ${dir}`}`,
			);
	};
	await mkdir(dir, { recursive: true });
	let composed = false;
	try {
		await reclaimOrphans(command, join(dirname(log), "reclaimed"));
		await step(
			"git",
			[
				"clone",
				"--quiet",
				"--depth",
				"1",
				"--branch",
				pin.tag,
				"https://gitlab.com/openid/conformance-suite.git",
				source,
			],
			budgetMs.clone,
		);
		const { stdout: head } = await step("git", ["-C", source, "rev-parse", "HEAD"], budgetMs.quick);
		if (head.trim() !== pin.commit) {
			throw new Error(
				`the suite's tag ${pin.tag} names ${head.trim()}, not the pinned ${pin.commit}`,
			);
		}
		const files = { cert: join(dir, "nginx-cert.pem"), key: join(dir, "nginx-key.pem") };
		await writeFile(files.cert, tls.cert);
		await writeFile(files.key, tls.key, { mode: 0o600 });
		await writeFile(join(dir, "override.yml"), composeOverride(host, files));
		const venv = join(dir, "python");
		await step("python3", ["-m", "venv", venv], budgetMs.quick);
		await step(join(venv, "bin", "pip"), ["install", "--quiet", ...pin.python], budgetMs.pip);
		// From here the containers may run: a failure stops them by Compose.
		composed = true;
		await step("docker", [...compose, "up", "--detach", "--quiet-pull"], budgetMs.up);
		const deadline = Date.now() + readyWithinMs;
		// Only the harness's certificate is trusted, by its fingerprint: an nginx answering with its own fails.
		const ca = tls.cert;
		for (;;) {
			signal?.throwIfAborted();
			try {
				if ((await getJson(`${suiteOrigin}/api/plan?length=1`, ca)).status === 200) break;
			} catch {}
			if (Date.now() > deadline)
				throw new Error(`the suite did not answer within ${readyWithinMs / 1000}s`);
			await sleep(2_000, signal);
		}
		const certificate = files.cert;
		const trusted = ca;
		return {
			scripts: join(source, "scripts"),
			python: join(venv, "bin", "python"),
			certificate,
			api: async (path) => {
				const answer = await getJson(`${suiteOrigin}/${path}`, trusted);
				if (answer.status !== 200)
					throw new Error(`the suite answered ${answer.status} to ${path}`);
				return answer.body;
			},
			stop,
		};
	} catch (error) {
		// Before Compose was asked for a container, there is nothing to stop: what was prepared goes.
		if (!composed) {
			const removed = await rm(dir, { recursive: true, force: true }).then(
				() => undefined,
				(failed: unknown) => failed,
			);
			if (removed !== undefined)
				throw new AggregateError([error, removed], `${String(error)}; and ${dir} stays`);
			throw error;
		}
		// The start's failure first, then each of the stop's.
		const stopped = await stop().then(
			() => undefined,
			(failed: unknown) => failed,
		);
		if (stopped !== undefined)
			throw new SuiteStopFailed(
				[error, ...(stopped instanceof AggregateError ? stopped.errors : [stopped])],
				`${String(error)}; and ${stopped instanceof Error ? stopped.message : String(stopped)}`,
			);
		throw error;
	}
}

/** Waits `ms`, or less where `signal` aborts. */
const sleep = (ms: number, signal?: AbortSignal) =>
	new Promise<void>((resolve, reject) => {
		const timer = setTimeout(resolve, ms);
		signal?.addEventListener(
			"abort",
			() => {
				clearTimeout(timer);
				reject(signal.reason);
			},
			{ once: true },
		);
	});
