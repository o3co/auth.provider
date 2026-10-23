/** A generated app booted as a deployment runs it: in the image its own Dockerfile builds. */
import { copyFileSync, mkdirSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { basename, join } from "node:path";
import { trialLayer } from "@mod/trial";
import { noSuchContainer, within } from "./container.ts";
import { buildWithin, docker, dockerStarted } from "./docker.ts";
import { refusalsIn } from "./refused.ts";

/** Why Docker cannot build and run the images, or nothing when it can. */
export function dockerMissing(): string | undefined {
	try {
		docker(["info", "--format", "{{.ServerVersion}}"]);
		return undefined;
	} catch (error) {
		const told = error as { stderr?: string; message: string };
		return told.stderr?.trim() || told.message;
	}
}

/** A pnpm workspace file that installs each named package from its tarball. */
export const overridesFile = (tarballs: Readonly<Record<string, string>>) =>
	`overrides:\n${Object.entries(tarballs)
		.map(([name, path]) => `  "${name}": "file:${path}"`)
		.join("\n")}\n`;

const freePort = () =>
	new Promise<number>((resolve) => {
		const server = createServer();
		server.listen(0, "127.0.0.1", () => {
			const { port } = server.address() as { port: number };
			server.close(() => resolve(port));
		});
	});

/**
 * Builds and runs apps' images, tagged `run`. The registry has no tarball of an unreleased version,
 * so each Dockerfile's `deps` stage is replaced by the same install, `--prod` in the Dockerfile's
 * own `base` stage, from the tarballs in `dir`; every other stage is built as written.
 */
export function images(
	run: string,
	tarballs: { readonly dir: string; readonly byName: Readonly<Record<string, string>> },
	scratch: string,
) {
	const built: string[] = [];
	const inContainer = Object.fromEntries(
		Object.entries(tarballs.byName).map(([name, path]) => [name, `/tarballs/${basename(path)}`]),
	);

	function build(app: string, name: string): string {
		const base = `${run}:base`;
		if (!built.includes(base)) {
			docker(["build", "-q", "--target", "base", "-t", base, app], buildWithin);
			built.push(base);
		}
		const deps = join(scratch, `deps-${name}`, "app");
		mkdirSync(deps, { recursive: true });
		copyFileSync(join(app, "package.json"), join(deps, "package.json"));
		writeFileSync(join(deps, "pnpm-workspace.yaml"), overridesFile(inContainer));
		const cache = join(scratch, "image-cache");
		const mounts = [`${deps}:/app`, `${tarballs.dir}:/tarballs:ro`, `${cache}:/cache`];
		docker(
			[
				"run",
				"--rm",
				...mounts.flatMap((mount) => ["-v", mount]),
				"-e",
				"COREPACK_HOME=/cache/corepack",
				"-e",
				"COREPACK_ENABLE_DOWNLOAD_PROMPT=0",
				base,
				"pnpm",
				"install",
				"--prod",
				"--no-frozen-lockfile",
				"--store-dir",
				"/cache/store",
			],
			buildWithin,
		);
		const image = `${run}:${name}`;
		docker(
			["build", "-q", "-t", image, "--build-context", `deps=${join(deps, "..")}`, app],
			buildWithin,
		);
		built.push(image);
		return image;
	}

	/**
	 * Runs the image, with `constraints` added to `docker run`: ready at /readyz, or refused (exit 78)
	 * with every refusal it wrote; anything else fails. `whileReady` runs on the ready container.
	 */
	async function booted(
		app: string,
		image: string,
		constraints: readonly string[] = [],
		whileReady?: (container: string) => void,
	): Promise<string> {
		const exposed = Object.keys(
			JSON.parse(docker(["image", "inspect", "--format", "{{json .Config.ExposedPorts}}", image])),
		);
		const listens = exposed[0]?.split("/")[0];
		if (exposed.length !== 1 || !listens)
			throw new Error(`${image} exposes ${exposed.length} ports, not one`);
		const port = await freePort();
		const local = await trialLayer(app, { redisUrl: "redis://127.0.0.1:1" });
		const conf = join(app, "config", "local.conf");
		writeFileSync(conf, local);
		const container = image.replace(":", "-");
		const child = dockerStarted([
			"run",
			"--rm",
			"--name",
			container,
			"-p",
			`127.0.0.1:${port}:${listens}`,
			"-v",
			`${conf}:/app/config/local.conf:ro`,
			"-e",
			"APP_CONFIG=config/local.conf,config/application.conf",
			...constraints,
			image,
		]);
		let output = "";
		child.stdout.on("data", (chunk) => {
			output += chunk;
		});
		child.stderr.on("data", (chunk) => {
			output += chunk;
		});
		const exited = new Promise<number | null>((resolve) =>
			child.once("exit", (code) => resolve(code)),
		);
		const ending = (...how: string[]) => {
			try {
				docker([...how, container]);
			} catch (error) {
				if (!noSuchContainer(error)) throw error;
			}
		};
		/** Fails the run with `error`, the container removed and its `docker run` let go first. */
		const failing = (error: unknown): never => {
			child.kill("SIGKILL");
			ending("rm", "-f");
			throw error;
		};
		const ended = () =>
			within(exited, 30_000, `${container} did not end within 30 seconds`).catch(failing);
		for (const until = Date.now() + 60_000; Date.now() < until; ) {
			if (child.exitCode !== null) break;
			const ready = await fetch(`http://127.0.0.1:${port}/readyz`, {
				signal: AbortSignal.timeout(5_000),
			}).then(
				(answer) => answer.status === 200,
				() => false,
			);
			if (ready) {
				// A look that fails still ends the container, within its deadline, before failing.
				let looked: { readonly failed: unknown } | undefined;
				try {
					whileReady?.(container);
				} catch (failed) {
					looked = { failed };
				}
				// One ended while ready, as a scene may end it, is gone already.
				if (child.exitCode === null) {
					try {
						ending("stop");
					} catch (error) {
						failing(error);
					}
				}
				await ended();
				if (looked !== undefined) throw looked.failed;
				return "ready";
			}
			await new Promise((resolve) => setTimeout(resolve, 250));
		}
		if (child.exitCode === null) {
			try {
				ending("rm", "-f");
			} catch (error) {
				failing(error);
			}
		}
		const code = await ended();
		const refusals = refusalsIn(output);
		if (code === 78 && refusals.length > 0) return `refused: ${refusals.join("; ")}`;
		throw new Error(`exited ${code}:\n${output}`);
	}

	/** Removes every image this run built; Docker's build cache stays for the next run. */
	const remove = () => {
		if (built.length > 0) docker(["image", "rm", "-f", ...built]);
	};

	return { build, booted, remove };
}
