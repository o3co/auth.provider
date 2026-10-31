/** A generated app booted as a deployment runs it: in the image its own Dockerfile builds. */
import { copyFileSync, mkdirSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { basename, join } from "node:path";
import { DockerFailed, docker, dockerWithin } from "@mod/docker-client";
import { trialLayer } from "@mod/trial";
import { carried } from "./carried/carried.ts";
import { type Container, withContainer } from "./containers/container.ts";
import { refusalsIn } from "./refused.ts";

export const commandWithin = dockerWithin.control;
export const buildWithin = dockerWithin.build;
const bootWithin = 3 * 60_000;

/** Why Docker cannot build and run the images, or nothing when it can. */
export async function dockerMissing(): Promise<string | undefined> {
	try {
		await docker(["info", "--format", "{{.ServerVersion}}"], commandWithin);
		return undefined;
	} catch (error) {
		if (error instanceof DockerFailed) return error.told.trim() || error.message;
		throw error;
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

/** A booted container once it answers ready (`answered`) or ends, within `ms`; neither fails, its output told. */
export async function settled(c: Container, answered: () => Promise<boolean>, ms: number) {
	let state: Awaited<ReturnType<Container["state"]>>;
	const ready = await c.until(
		async () => {
			state = await c.state();
			return !state?.running || (await answered());
		},
		250,
		ms,
	);
	if (!ready)
		throw new Error(`neither ready nor ended within ${ms / 1000} seconds:\n${await c.logs()}`);
	const now = state;
	if (now === undefined) throw new Error(`${c.name} was removed while booting`);
	return now;
}

/**
 * The `docker run` arguments of an install from the tarballs in the base stage, as `user` (the
 * runner's own `uid:gid`), its home and corepack's under the mounted cache: what it writes into the
 * mounted directories is the runner's, removed by the runner with no privilege.
 */
export const installArguments = (p: {
	readonly mounts: readonly string[];
	readonly base: string;
	readonly user: string;
}) => [
	...p.mounts.flatMap((mount) => ["-v", mount]),
	"--user",
	p.user,
	"-e",
	"HOME=/cache/home",
	"-e",
	"COREPACK_HOME=/cache/corepack",
	"-e",
	"COREPACK_ENABLE_DOWNLOAD_PROMPT=0",
	p.base,
	"pnpm",
	"install",
	"--prod",
	"--no-frozen-lockfile",
	"--store-dir",
	"/cache/store",
];

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

	async function build(app: string, name: string): Promise<string> {
		const base = `${run}:base`;
		if (!built.includes(base)) {
			await docker(["build", "-q", "--target", "base", "-t", base, app], buildWithin);
			built.push(base);
		}
		const deps = join(scratch, `deps-${name}`, "app");
		mkdirSync(deps, { recursive: true });
		copyFileSync(join(app, "package.json"), join(deps, "package.json"));
		writeFileSync(join(deps, "pnpm-workspace.yaml"), overridesFile(inContainer));
		const cache = join(scratch, "image-cache");
		// Made here, the runner's: Docker makes a missing directory it mounts as root.
		mkdirSync(join(cache, "home"), { recursive: true });
		const mounts = [`${deps}:/app`, `${tarballs.dir}:/tarballs:ro`, `${cache}:/cache`];
		const user = `${process.getuid?.() ?? 0}:${process.getgid?.() ?? 0}`;
		await withContainer({ run, purpose: `install-${name}`, within: buildWithin }, (c) =>
			c.run(installArguments({ mounts, base, user })),
		);
		const image = `${run}:${name}`;
		await docker(
			["build", "-q", "-t", image, "--build-context", `deps=${join(deps, "..")}`, app],
			buildWithin,
		);
		built.push(image);
		return image;
	}

	/**
	 * Runs the image, with `constraints` added to `docker run`: ready at /readyz, or refused (exit 78)
	 * with every refusal it wrote; anything else fails. `whileReady` looks at the ready container.
	 */
	async function booted(
		app: string,
		image: string,
		constraints: readonly string[] = [],
		whileReady?: (container: Container) => Promise<void>,
	): Promise<string> {
		const exposed = Object.keys(
			JSON.parse(
				await docker(
					["image", "inspect", "--format", "{{json .Config.ExposedPorts}}", image],
					commandWithin,
				),
			),
		);
		const listens = exposed[0]?.split("/")[0];
		if (exposed.length !== 1 || !listens)
			throw new Error(`${image} exposes ${exposed.length} ports, not one`);
		const port = await freePort();
		const local = await trialLayer(app, { redisUrl: "redis://127.0.0.1:1" });
		const conf = join(app, "config", "local.conf");
		writeFileSync(conf, local);
		const purpose = `boot-${image.slice(image.indexOf(":") + 1)}`;
		return withContainer({ run, purpose, within: bootWithin }, async (c) => {
			await c.run([
				"-d",
				"-p",
				`127.0.0.1:${port}:${listens}`,
				"-v",
				`${conf}:/app/config/local.conf:ro`,
				"-e",
				"APP_CONFIG=config/local.conf,config/application.conf",
				...constraints,
				image,
			]);
			const answered = () =>
				fetch(`http://127.0.0.1:${port}/readyz`, { signal: AbortSignal.timeout(5_000) }).then(
					(answer) => answer.status === 200,
					() => false,
				);
			const state = await settled(c, answered, 60_000);
			if (state.running) {
				await whileReady?.(c);
				return "ready";
			}
			const output = await c.logs();
			const refusals = refusalsIn(output);
			if (state.exitCode === 78 && refusals.length > 0) return `refused: ${refusals.join("; ")}`;
			throw new Error(`exited ${state.exitCode}:\n${output}`);
		});
	}

	/** Removes every image this run built; Docker's build cache stays for the next run. */
	const remove = async () => {
		if (built.length > 0) await docker(["image", "rm", "-f", ...built], commandWithin);
	};

	/** Each path `image` holds a package manager at. */
	const carriedBy = (image: string) =>
		withContainer(
			{ run, purpose: `tools-${image.slice(image.indexOf(":") + 1)}`, within: commandWithin },
			(c) => carried(c, image),
		);

	return { build, booted, carriedBy, remove };
}
