/** A generated app booted as a deployment runs it: in the image its own Dockerfile builds. */
import { execFileSync, spawn } from "node:child_process";
import { copyFileSync, mkdirSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { basename, join } from "node:path";
import { trialLayer } from "@mod/trial";
import { refusalsIn } from "./refused.ts";

const docker = (args: readonly string[]) =>
	execFileSync("docker", args, { encoding: "utf8", stdio: "pipe" }).trim();

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
			docker(["build", "-q", "--target", "base", "-t", base, app]);
			built.push(base);
		}
		const deps = join(scratch, `deps-${name}`, "app");
		mkdirSync(deps, { recursive: true });
		copyFileSync(join(app, "package.json"), join(deps, "package.json"));
		writeFileSync(join(deps, "pnpm-workspace.yaml"), overridesFile(inContainer));
		const cache = join(scratch, "image-cache");
		const mounts = [`${deps}:/app`, `${tarballs.dir}:/tarballs:ro`, `${cache}:/cache`];
		docker([
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
		]);
		const image = `${run}:${name}`;
		docker(["build", "-q", "-t", image, "--build-context", `deps=${join(deps, "..")}`, app]);
		built.push(image);
		return image;
	}

	/** Runs the image: ready at /readyz, or refused (exit 78) with every refusal it wrote; anything else fails. */
	async function booted(app: string, image: string): Promise<string> {
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
		const child = spawn("docker", [
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
		for (let waited = 0; waited < 60_000; waited += 250) {
			if (child.exitCode !== null) break;
			const ready = await fetch(`http://127.0.0.1:${port}/readyz`).then(
				(answer) => answer.status === 200,
				() => false,
			);
			if (ready) {
				docker(["stop", container]);
				await exited;
				return "ready";
			}
			await new Promise((resolve) => setTimeout(resolve, 250));
		}
		if (child.exitCode === null) docker(["rm", "-f", container]);
		const code = await exited;
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
