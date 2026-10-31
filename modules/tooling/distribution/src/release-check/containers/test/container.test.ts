import { type Docker, DockerFailed, type DockerFailure } from "@mod/docker-client";
import { describe, expect, it } from "vitest";
import { type Container, type ContainerOptions, sweptRun, withContainer } from "../container.ts";

const failed = (kind: DockerFailure, command: string) =>
	new DockerFailed(kind, command, `docker ${command}: ${kind}`);

/** A daemon in memory: the containers it holds, and each command with the time it was given. */
function daemon(
	behave: {
		readonly [command: string]: (
			args: readonly string[],
			within: number,
			signal?: AbortSignal,
		) => Promise<string>;
	} = {},
) {
	const held = new Set<string>();
	const labels = new Map<string, string>();
	const calls: { readonly args: readonly string[]; readonly within: number }[] = [];
	const nameIn = (args: readonly string[]) => args[args.indexOf("--name") + 1] ?? "";
	const plain: Record<string, (args: readonly string[]) => Promise<string>> = {
		run: async (args) => {
			held.add(nameIn(args));
			labels.set(nameIn(args), args[args.indexOf("--label") + 1]?.split("=")[1] ?? "");
			return args.includes("-d") ? "id" : "";
		},
		ps: async (args) => {
			const filter = args[args.indexOf("--filter") + 1] ?? "";
			const run = filter.startsWith("label=release-check.run=") ? filter.split("=")[2] : undefined;
			return [...held]
				.filter((name) => run === undefined || labels.get(name) === run)
				.map((name) => `${name}\t${labels.get(name) ?? ""}`)
				.join("\n");
		},
		rm: async (args) => {
			held.delete(args.at(-1) ?? "");
			return "";
		},
		inspect: async (args) => {
			if (!held.has(args.at(-1) ?? "")) throw failed("absent", "inspect");
			return "true 0";
		},
	};
	const docker: Docker = async (args, within, told) => {
		calls.push({ args, within });
		const command = args[0] ?? "";
		const own = behave[command];
		if (own) return own(args, within, told?.signal);
		return (plain[command] ?? (async () => ""))(args);
	};
	return { docker, held, labels, calls, nameIn };
}

const options = (docker: Docker, within = 1_000): ContainerOptions => ({
	run: "release-check-1",
	purpose: "install-simple-web",
	within,
	teardownWithin: 1_000,
	docker,
});
const outcome = <T>(running: Promise<T>): Promise<{ value?: T; error?: unknown }> =>
	running.then(
		(value) => ({ value }),
		(error: unknown) => ({ error }),
	);

describe("a container a check runs", () => {
	it("is named for its run, labelled with it, and removed once done", async () => {
		const d = daemon();
		const value = await withContainer(options(d.docker), async (c) => {
			await c.run(["base", "pnpm", "install"]);
			return c.name;
		});
		expect(value).toMatch(/^release-check-1-install-simple-web-\d+$/);
		expect(d.calls[0]?.args).toEqual([
			"run",
			"--name",
			value,
			"--label",
			"release-check.run=release-check-1",
			"base",
			"pnpm",
			"install",
		]);
		expect(d.held.size).toBe(0);
		expect(d.calls.map((c) => c.args[0])).toEqual(["run", "rm", "inspect"]);
		// Its anonymous volumes go with it, as an image's VOLUME would otherwise stay behind.
		expect(d.calls[1]?.args).toEqual(["rm", "-f", "-v", value]);
	});

	it("never shares a name with another of the same run and purpose", async () => {
		const d = daemon();
		const names = await Promise.all(
			[1, 2].map(() => withContainer(options(d.docker), async (c) => c.name)),
		);
		expect(new Set(names).size).toBe(2);
	});

	it("is removed where the daemon made it and its client then ran past the deadline", async () => {
		const d = daemon({
			run: async (args, within) => {
				d.held.add(d.nameIn(args));
				await new Promise((resolve) => setTimeout(resolve, within));
				throw failed("timeout", "run");
			},
		});
		const ran = await outcome(withContainer(options(d.docker, 50), (c) => c.run(["base"])));
		expect(ran).toMatchObject({ error: { kind: "timeout" } });
		expect(d.held.size).toBe(0);
	});

	it("is removed where its client ended early, failing, after the daemon made it", async () => {
		const d = daemon({
			run: async (args) => {
				d.held.add(d.nameIn(args));
				throw failed("failed", "run");
			},
		});
		expect(await outcome(withContainer(options(d.docker), (c) => c.run(["base"])))).toMatchObject({
			error: { kind: "failed", command: "run" },
		});
		expect(d.held.size).toBe(0);
	});

	it("keeps both failures where no docker client can start, its teardown unable to tell it gone", async () => {
		const d = daemon({
			run: async () => {
				throw failed("unstarted", "run");
			},
			rm: async () => {
				throw failed("unstarted", "rm");
			},
		});
		const ran = await outcome(withContainer(options(d.docker), (c) => c.run(["base"])));
		expect(ran.error).toBeInstanceOf(AggregateError);
		expect((ran.error as AggregateError).errors).toMatchObject([
			{ kind: "unstarted", command: "run" },
			{ kind: "unstarted", command: "rm" },
		]);
	});

	it("is removed where the work given it fails, that failure the one thrown", async () => {
		const d = daemon();
		const ran = await outcome(
			withContainer(options(d.docker), async (c) => {
				await c.run(["-d", "image"]);
				throw new Error("the look failed");
			}),
		);
		expect(ran).toMatchObject({ error: { message: "the look failed" } });
		expect(d.held.size).toBe(0);
	});

	it("fails where its removal fails, beside the work's own failure where there was one", async () => {
		const refusing = async () => {
			throw failed("failed", "rm");
		};
		const done = daemon({ rm: refusing });
		expect(
			await outcome(withContainer(options(done.docker), (c) => c.run(["-d", "image"]))),
		).toMatchObject({
			error: { kind: "failed", command: "rm" },
		});
		const failing = daemon({ rm: refusing });
		const ran = await outcome(
			withContainer(options(failing.docker), async (c) => {
				await c.run(["-d", "image"]);
				throw new Error("the look failed");
			}),
		);
		expect((ran.error as AggregateError).errors).toMatchObject([
			{ message: "the look failed" },
			{ kind: "failed", command: "rm" },
		]);
	});

	it("fails where, once removed, inspecting it still finds it or cannot tell", async () => {
		const kept = daemon({ rm: async () => "" });
		expect(
			await outcome(withContainer(options(kept.docker), (c) => c.run(["-d", "image"]))),
		).toMatchObject({
			error: { message: expect.stringMatching(/still there/) },
		});
		const unsure = daemon({
			inspect: async () => {
				throw failed("failed", "inspect");
			},
		});
		expect(
			await outcome(withContainer(options(unsure.docker), (c) => c.run(["-d", "image"]))),
		).toMatchObject({
			error: { kind: "failed", command: "inspect" },
		});
	});

	it("refuses its work's commands once its removal is asked, so it is never made again", async () => {
		const d = daemon();
		let after: unknown;
		await withContainer(options(d.docker), async (c) => {
			await c.run(["-d", "image"]);
			await c.removed();
			after = await c.run(["-d", "image"]).catch((error: unknown) => error);
		});
		expect(after).toMatchObject({ kind: "timeout" });
		expect(d.calls.map((c) => c.args[0])).toEqual(["run", "rm", "inspect"]);
		expect(d.held.size).toBe(0);
	});

	it("is removed once, however often its removal is asked", async () => {
		const d = daemon();
		await withContainer(options(d.docker), async (c) => {
			await c.run(["-d", "image"]);
			await c.removed();
			await c.removed();
		});
		expect(d.calls.filter((c) => c.args[0] === "rm")).toHaveLength(1);
	});

	it("gives each command what is left of one deadline, and its removal a time of its own", async () => {
		const d = daemon();
		await withContainer(options(d.docker, 1_000), async (c) => {
			await c.run(["-d", "image"]);
			await new Promise((resolve) => setTimeout(resolve, 30));
			await c.on("exec", "true");
		});
		const [run, exec, rm] = d.calls;
		expect(run?.within).toBeLessThanOrEqual(1_000);
		expect(exec?.within).toBeLessThan((run?.within ?? 0) - 20);
		expect(rm?.within).toBeGreaterThan(900);
	});
});

describe("a work that outlasts its deadline", () => {
	it("is cut there, the container removed, though the work never ends", async () => {
		const d = daemon();
		const began = performance.now();
		const ran = await outcome(
			withContainer(options(d.docker, 20), async (c) => {
				await c.run(["-d", "image"]);
				await new Promise(() => {});
			}),
		);
		expect(ran.error).toMatchObject({ message: expect.stringMatching(/did not end within/) });
		expect(performance.now() - began).toBeLessThan(1_000);
		expect(d.held.size).toBe(0);
	});

	it("fails though the work would succeed later, nothing it asks after taken", async () => {
		const d = daemon();
		const ran = await outcome(
			withContainer(options(d.docker, 20), async (c) => {
				await new Promise((resolve) => setTimeout(resolve, 100));
				await c.run(["-d", "image"]);
				return "late";
			}),
		);
		expect(ran).toMatchObject({ error: { message: expect.stringMatching(/did not end within/) } });
		await new Promise((resolve) => setTimeout(resolve, 150));
		expect(d.calls.map((c) => c.args[0])).toEqual(["rm", "inspect"]);
		expect(d.held.size).toBe(0);
	});

	it("fails though the work answers before its timer, where it held the clock past its deadline", async () => {
		const d = daemon();
		const ran = await outcome(
			withContainer(options(d.docker, 20), async () => {
				const until = performance.now() + 60;
				while (performance.now() < until) {}
				return "late";
			}),
		);
		expect(ran).toMatchObject({ error: { message: expect.stringMatching(/did not end within/) } });
		expect(d.calls.map((c) => c.args[0])).toEqual(["rm", "inspect"]);
	});

	it("has a command still running at its end stopped", async () => {
		let stopped = false;
		const d = daemon({
			exec: (_args, _within, signal) =>
				new Promise<string>((_, fail) =>
					signal?.addEventListener("abort", () => {
						stopped = true;
						fail(new DockerFailed("timeout", "exec", "stopped"));
					}),
				),
		});
		await outcome(withContainer(options(d.docker, 20), (c) => c.on("exec", "true")));
		expect(stopped).toBe(true);
	});
});

describe("a container used where another's work runs", () => {
	it("refuses every command once closed, though asked from inside another container's work or look", async () => {
		const first = daemon();
		const second = daemon();
		let closed: Container | undefined;
		await withContainer(options(first.docker), async (c) => {
			closed = c;
		});
		const asked: unknown[] = [];
		await withContainer(options(second.docker), async (c) => {
			asked.push(await closed?.run(["-d", "image"]).catch((error: unknown) => error));
			await c.until(
				async () => {
					asked.push(await closed?.run(["-d", "image"]).catch((error: unknown) => error));
					return true;
				},
				5,
				1_000,
			);
		});
		expect(asked).toMatchObject([{ kind: "timeout" }, { kind: "timeout" }]);
		expect(first.calls.map((c) => c.args[0])).toEqual(["rm", "inspect"]);
		expect(first.held.size).toBe(0);
	});
});

describe("a work that fails while a look of it still waits", () => {
	it("leaves no timer of the look behind once it is removed", async () => {
		const d = daemon();
		const timers = () =>
			process.getActiveResourcesInfo().filter((kind) => kind === "Timeout").length;
		const before = timers();
		const ran = await outcome(
			withContainer(options(d.docker, 5_000), (c) =>
				Promise.all([
					c.until(() => new Promise<boolean>(() => {}), 300, 300),
					Promise.reject(new Error("the other look failed")),
				]),
			),
		);
		expect(ran).toMatchObject({ error: { message: "the other look failed" } });
		await new Promise((resolve) => setImmediate(resolve));
		expect(timers()).toBeLessThanOrEqual(before);
	});
});

describe("a look again and again, within the container's deadline", () => {
	it("holds once the look holds", async () => {
		const d = daemon();
		let looks = 0;
		const held = await withContainer(options(d.docker), (c) =>
			c.until(async () => ++looks === 3, 1),
		);
		expect(held).toBe(true);
		expect(looks).toBe(3);
	});

	it("gives up by the clock however long each look takes, and begins none past it", async () => {
		const d = daemon();
		const starts: number[] = [];
		const slow = async () => {
			starts.push(performance.now());
			await new Promise((resolve) => setTimeout(resolve, 40));
			return false;
		};
		const held = await withContainer(options(d.docker, 5_000), (c) => c.until(slow, 1, 100));
		const ended = performance.now();
		expect(held).toBe(false);
		// The first look begins once the time is set, so the time ends 100 ms after it at the latest:
		// a look begun from then on began past it, however slow the machine is.
		const [first = 0] = starts;
		expect(starts.filter((at) => at >= first + 100)).toEqual([]);
		// It gave up by the clock, not by running out of looks: well before the container's own time.
		expect(ended - first).toBeLessThan(2_000);
	});

	it("gives a look's commands no more than the look's own time", async () => {
		const d = daemon();
		await withContainer(options(d.docker, 60_000), (c) =>
			c.until(async () => (await c.state()) === undefined, 5, 50),
		);
		const looks = d.calls.filter(
			(call) =>
				call.args[0] === "inspect" && call.args.includes("{{.State.Running}} {{.State.ExitCode}}"),
		);
		expect(looks.length).toBeGreaterThan(0);
		for (const look of looks) expect(look.within).toBeLessThanOrEqual(50);
	});

	it("takes no answer that comes past its time, however the look ends", async () => {
		const d = daemon();
		const began = performance.now();
		const late = await withContainer(options(d.docker, 60_000), (c) =>
			c.until(() => new Promise<boolean>((resolve) => setTimeout(() => resolve(true), 200)), 5, 50),
		);
		expect(late).toBe(false);
		const never = await withContainer(options(d.docker, 60_000), (c) =>
			c.until(() => new Promise<boolean>(() => {}), 5, 50),
		);
		expect(never).toBe(false);
		expect(performance.now() - began).toBeLessThan(1_000);
	});

	it("lets a look that ran past its time ask nothing more: no command follows the removal", async () => {
		const d = daemon();
		let lateAsked: unknown;
		const ran = await outcome(
			withContainer(options(d.docker, 60_000), (c) =>
				c.until(
					async () => {
						await new Promise((resolve) => setTimeout(resolve, 80));
						lateAsked = await c.run(["-d", "image"]).catch((error: unknown) => error);
						return true;
					},
					5,
					20,
				),
			),
		);
		expect(ran.value).toBe(false);
		await new Promise((resolve) => setTimeout(resolve, 150));
		expect(lateAsked).toMatchObject({ kind: "timeout" });
		expect(d.calls.map((c) => c.args[0])).toEqual(["rm", "inspect"]);
		expect(d.held.size).toBe(0);
	});

	it("has a look's command still running at the look's time stopped", async () => {
		let stopped = false;
		const d = daemon({
			inspect: (args, _within, signal) =>
				args.includes("{{.State.Running}} {{.State.ExitCode}}")
					? new Promise<string>((_, fail) =>
							signal?.addEventListener("abort", () => {
								stopped = true;
								fail(new DockerFailed("timeout", "inspect", "stopped"));
							}),
						)
					: Promise.reject(new DockerFailed("absent", "inspect", "gone")),
		});
		await withContainer(options(d.docker, 60_000), (c) =>
			c.until(async () => (await c.state()) !== undefined, 5, 20),
		);
		expect(stopped).toBe(true);
	});

	it("reads a look's command running out of time with the look as the look not holding, not as a failure", async () => {
		const d = daemon({
			inspect: async (args, within) => {
				if (!args.includes("{{.State.Running}} {{.State.ExitCode}}"))
					throw failed("absent", "inspect");
				// The command's own timer, given what is left of the look's time, rings first.
				await new Promise((resolve) => setTimeout(resolve, Math.max(0, within - 5)));
				throw failed("timeout", "inspect");
			},
		});
		const held = await withContainer(options(d.docker, 60_000), (c) =>
			c.until(async () => (await c.state())?.running === false, 5, 40),
		);
		expect(held).toBe(false);
	});

	it("still fails on a look's command that fails otherwise", async () => {
		const d = daemon({
			inspect: async (args) => {
				if (!args.includes("{{.State.Running}} {{.State.ExitCode}}"))
					throw failed("absent", "inspect");
				throw failed("failed", "inspect");
			},
		});
		const ran = await outcome(
			withContainer(options(d.docker, 60_000), (c) =>
				c.until(async () => (await c.state()) === undefined, 5, 40),
			),
		);
		expect(ran).toMatchObject({ error: { kind: "failed", command: "inspect" } });
	});

	it("gives commands after the look the container's time again", async () => {
		const d = daemon();
		await withContainer(options(d.docker, 60_000), async (c) => {
			await c.until(async () => true, 5, 50);
			await c.on("exec", "true");
		});
		expect(d.calls.find((call) => call.args[0] === "exec")?.within).toBeGreaterThan(50_000);
	});

	it("gives up sooner where a shorter time is asked", async () => {
		const d = daemon();
		const began = performance.now();
		await withContainer(options(d.docker, 5_000), (c) => c.until(async () => false, 5, 50));
		expect(performance.now() - began).toBeLessThan(1_000);
	});
});

describe("a run's containers swept by its label", () => {
	it("removes one the daemon made only after the container's own removal, looking again after a while", async () => {
		const d = daemon({
			run: async (args, within) => {
				const name = d.nameIn(args);
				setTimeout(() => {
					d.held.add(name);
					d.labels.set(name, "release-check-1");
				}, 40);
				await new Promise((resolve) => setTimeout(resolve, within));
				throw failed("timeout", "run");
			},
		});
		await outcome(withContainer(options(d.docker, 20), (c) => c.run(["-d", "image"])));
		const swept = await sweptRun("release-check-1", { docker: d.docker, settle: 80 });
		expect(swept).toHaveLength(1);
		expect(d.held.size).toBe(0);
		// The one swept goes with its anonymous volumes too.
		const removals = d.calls.filter((c) => c.args[0] === "rm").map((c) => c.args.slice(0, 3));
		expect(removals.length).toBeGreaterThan(0);
		for (const args of removals) expect(args).toEqual(["rm", "-f", "-v"]);
	});

	it("fails where one is still there after it, naming it", async () => {
		const d = daemon({ rm: async () => "" });
		d.held.add("release-check-1-boot-simple-web-9");
		d.labels.set("release-check-1-boot-simple-web-9", "release-check-1");
		await expect(sweptRun("release-check-1", { docker: d.docker, settle: 1 })).rejects.toThrow(
			/release-check-1-boot-simple-web-9/,
		);
	});

	it("tries every name though Docker refuses one, telling the refused name at the end", async () => {
		const d = daemon({
			rm: async (args) => {
				const name = args.at(-1) ?? "";
				if (name === "release-check-1-boot-b-2") throw failed("failed", "rm");
				d.held.delete(name);
				return "";
			},
		});
		for (const name of [
			"release-check-1-boot-a-1",
			"release-check-1-boot-b-2",
			"release-check-1-boot-c-3",
		]) {
			d.held.add(name);
			d.labels.set(name, "release-check-1");
		}
		await expect(sweptRun("release-check-1", { docker: d.docker, settle: 1 })).rejects.toThrow(
			/release-check-1-boot-b-2/,
		);
		expect([...d.held]).toEqual(["release-check-1-boot-b-2"]);
	});

	it("touches no container of another run", async () => {
		const d = daemon();
		d.held.add("release-check-2-boot-a-1");
		d.labels.set("release-check-2-boot-a-1", "release-check-2");
		expect(await sweptRun("release-check-1", { docker: d.docker, settle: 1 })).toEqual([]);
		expect(d.held.has("release-check-2-boot-a-1")).toBe(true);
	});
});

describe("a look whose work ends inside it", () => {
	it("ends at once, though its look then waits on nothing", async () => {
		const d = daemon();
		const began = performance.now();
		const held = await withContainer(options(d.docker, 60_000), (c) =>
			c.until(
				async () => {
					await c.removed();
					return new Promise<boolean>(() => {});
				},
				5,
				5_000,
			),
		);
		expect(held).toBe(false);
		expect(performance.now() - began).toBeLessThan(1_000);
	});
});
