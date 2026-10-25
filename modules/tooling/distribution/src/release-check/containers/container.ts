/** A container a check runs, owned for its whole life: named, labelled, timed, and removed. */
import { AsyncLocalStorage } from "node:async_hooks";
import { type Docker, DockerFailed, docker as dockerClient } from "./docker.ts";

export interface ContainerOptions {
	/** The check's run: part of each name, and the label every container of it carries. */
	readonly run: string;
	/** What the container is for: part of its name. */
	readonly purpose: string;
	/** The work's one deadline, in ms, every command and look given what is left of it. */
	readonly within: number;
	/** The removal's own time, in ms, so a work out of time is still removed. */
	readonly teardownWithin?: number;
	readonly docker?: Docker;
}

export interface Container {
	readonly name: string;
	/** `docker run` of it, named and labelled: with `-d`, answered once it starts; else once it ends. */
	run(args: readonly string[]): Promise<string>;
	/** `docker <command> <name> <rest>`, within what is left of the deadline. */
	on(command: string, ...rest: string[]): Promise<string>;
	logs(): Promise<string>;
	/** Whether it runs, and its exit code; none where it is gone. */
	state(): Promise<{ readonly running: boolean; readonly exitCode: number } | undefined>;
	/** Whether `check` holds before the deadline, or `most` ms; looked at every `pause` ms, none begun past it. */
	until(check: () => Promise<boolean>, pause: number, most?: number): Promise<boolean>;
	/** Removes it and makes sure it is gone; asked again, it does nothing more. */
	removed(): Promise<void>;
}

let made = 0;
const absent = (error: unknown) => error instanceof DockerFailed && error.kind === "absent";
/** Waits `ms`, or less where `signal` ends first; its timer cleared either way. */
const pause = (ms: number, signal?: AbortSignal) =>
	new Promise<void>((resolve) => {
		const done = () => {
			clearTimeout(timer);
			signal?.removeEventListener("abort", done);
			resolve();
		};
		const timer = setTimeout(done, Math.max(0, ms));
		signal?.addEventListener("abort", done, { once: true });
	});

/** `running`, or what `late` gives once `ms` pass or `signal` ends first; its timer cleared either way, a late failure of `running` let be. */
async function cut<T>(
	running: Promise<T>,
	ms: number,
	late: () => T,
	signal?: AbortSignal,
): Promise<T> {
	running.catch(() => undefined);
	// Ended already, inside the very look it cuts: an abort is never heard again.
	if (signal?.aborted) return late();
	let ending = () => {};
	const deadline = new Promise<T>((resolve, fail) => {
		ending = () => {
			try {
				resolve(late());
			} catch (error) {
				fail(error);
			}
		};
	});
	const timer = setTimeout(() => ending(), Math.max(0, ms));
	const ended = () => ending();
	signal?.addEventListener("abort", ended, { once: true });
	try {
		return await Promise.race([running, deadline]);
	} finally {
		clearTimeout(timer);
		signal?.removeEventListener("abort", ended);
	}
}

/** The time and the signal a command is asked under: the work's, or a look's while it runs. */
interface Scope {
	readonly stop: number;
	readonly signal: AbortSignal;
}

/** Runs `use` on a container of its own, removing it at the end however `use` ends, or once its deadline passes. */
export async function withContainer<T>(
	options: ContainerOptions,
	use: (container: Container) => Promise<T>,
): Promise<T> {
	const docker = options.docker ?? dockerClient;
	made += 1;
	const name = `${options.run}-${options.purpose}-${made}`;
	// Closed at the work's end: a command asked after it is refused, and one running is stopped.
	const closing = new AbortController();
	// Its own, following a look's continuation: a look of another container's is never this one's.
	const looking = new AsyncLocalStorage<Scope>();
	const scope: Scope = { stop: performance.now() + options.within, signal: closing.signal };
	let removing: Promise<void> | undefined;

	/** Every command of the work, under its scope: refused once it is over, stopped when it ends. */
	const ask = (args: readonly string[], merged = false) => {
		const under = looking.getStore() ?? scope;
		const time = Math.min(under.stop, scope.stop) - performance.now();
		// Its own end is always heard, whatever work or look asks.
		if (closing.signal.aborted || under.signal.aborted || time <= 0) {
			const command = args[0] ?? "";
			return Promise.reject(
				new DockerFailed("timeout", command, `docker ${command} was asked past its time`),
			);
		}
		const signal = under === scope ? scope.signal : AbortSignal.any([under.signal, scope.signal]);
		return docker(args, time, { merged, signal });
	};

	const removal = async () => {
		const until = performance.now() + (options.teardownWithin ?? 30_000);
		const time = () => Math.max(0, until - performance.now());
		await docker(["rm", "-f", "-v", name], time()).catch((error: unknown) => {
			if (!absent(error)) throw error;
		});
		const still = await docker(["inspect", "--format", "{{.Id}}", name], time()).then(
			() => true,
			(error: unknown) => {
				if (absent(error)) return false;
				throw error;
			},
		);
		if (still) throw new Error(`${name} is still there after its removal`);
	};

	const container: Container = {
		name,
		run: (args) =>
			ask(["run", "--name", name, "--label", `release-check.run=${options.run}`, ...args]),
		on: (command, ...rest) => ask([command, name, ...rest]),
		logs: () => ask(["logs", name], true),
		state: async () => {
			const said = await ask([
				"inspect",
				"--format",
				"{{.State.Running}} {{.State.ExitCode}}",
				name,
			]).catch((error: unknown) => {
				if (absent(error)) return undefined;
				throw error;
			});
			if (said === undefined) return undefined;
			const [running, exitCode] = said.split(" ");
			return { running: running === "true", exitCode: Number(exitCode) };
		},
		until: async (check, every, most = Number.POSITIVE_INFINITY) => {
			const outer = looking.getStore() ?? scope;
			const stop = Math.min(outer.stop, performance.now() + most);
			const ended = new AbortController();
			const look: Scope = { stop, signal: AbortSignal.any([outer.signal, ended.signal]) };
			try {
				while (performance.now() < stop && !look.signal.aborted) {
					// A look running at the time is cut there and stopped; an answer past it is not taken.
					// Its commands have no more time than the look: one out of time is the look not holding; any other failure is told.
					const looked = looking.run(look, check).catch((error: unknown) => {
						if (error instanceof DockerFailed && error.kind === "timeout") return false;
						throw error;
					});
					const held = await cut(looked, stop - performance.now(), () => false, look.signal);
					if (held && performance.now() < stop) return true;
					if (look.signal.aborted) return false;
					await pause(Math.min(every, stop - performance.now()), look.signal);
				}
				return false;
			} finally {
				ended.abort();
			}
		},
		removed: () => {
			// Its work's commands end first: none of them makes it again once its removal starts.
			closing.abort();
			removing ??= removal();
			return removing;
		},
	};

	let value: T;
	const late = () => {
		throw new Error(`${name}'s work did not end within ${options.within / 1000} seconds`);
	};
	try {
		value = await cut(
			looking.run(scope, () => use(container)),
			scope.stop - performance.now(),
			late,
		);
		// An answer that held the clock past the deadline settles before the timer: the clock tells it.
		if (performance.now() > scope.stop) late();
	} catch (failure) {
		closing.abort();
		try {
			await container.removed();
		} catch (removalFailure) {
			const told = (error: unknown) => (error instanceof Error ? error.message : String(error));
			throw new AggregateError(
				[failure, removalFailure],
				`${told(failure)}; and ${name}'s removal failed: ${told(removalFailure)}`,
			);
		}
		throw failure;
	}
	closing.abort();
	await container.removed();
	return value;
}

export interface SweepOptions {
	readonly docker?: Docker;
	readonly within?: number;
	/** How long to wait before looking again, for a container whose making was seen only late. */
	readonly settle?: number;
}

async function labelled(docker: Docker, within: number, run: string) {
	const filter = `label=release-check.run=${run}`;
	const said = await docker(
		["ps", "-a", "--filter", filter, "--format", '{{.Names}}\t{{.Label "release-check.run"}}'],
		within,
	);
	return said
		.split("\n")
		.filter(Boolean)
		.map((line) => {
			const [name = "", of = ""] = line.split("\t");
			return { name, run: of };
		});
}

/** Removes each name, every one tried though Docker refuses one; the refusals, by name. */
async function removedAll(docker: Docker, within: number, names: readonly string[]) {
	const refused = new Map<string, unknown>();
	for (const name of names) {
		await docker(["rm", "-f", "-v", name], within).catch((error: unknown) => {
			if (!absent(error)) refused.set(name, error);
		});
	}
	return refused;
}

/** Removes `run`'s containers, again after `settle` ms, failing on any still there: the cleanup the check stands by. */
export async function sweptRun(
	run: string,
	options: SweepOptions = {},
): Promise<readonly string[]> {
	const docker = options.docker ?? dockerClient;
	const within = options.within ?? 60_000;
	const swept: string[] = [];
	const refused = new Map<string, unknown>();
	for (const pass of [0, 1]) {
		if (pass === 1) await pause(options.settle ?? 3_000);
		const names = (await labelled(docker, within, run)).map((c) => c.name);
		for (const [name, error] of await removedAll(docker, within, names)) refused.set(name, error);
		swept.push(...names.filter((name) => !swept.includes(name) && !refused.has(name)));
	}
	const left = (await labelled(docker, within, run)).map((c) => c.name);
	if (left.length > 0) {
		const why = (name: string) => {
			const error = refused.get(name);
			return error instanceof Error ? `${name} (${error.message})` : name;
		};
		throw new Error(`containers of ${run} are still there: ${left.map(why).join(", ")}`, {
			cause: [...refused.values()],
		});
	}
	return swept;
}
