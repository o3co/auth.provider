/** The resolver's helper processes in an app's image, run as a deployment constrains it. */
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { docker } from "@mod/docker-client";
import type { Container } from "../containers/container.ts";
import { pidsCurrent } from "./cgroup.ts";

/** The part of `images` a scene drives: booting the image with constraints, a look while ready. */
interface Booting {
	booted(
		app: string,
		image: string,
		constraints?: readonly string[],
		whileReady?: (container: Container) => Promise<void>,
	): Promise<string>;
}

const inside = (c: Container, ...command: string[]) => c.on("exec", ...command);
/** The command lines of the container's processes. */
const processes = async (c: Container) => (await inside(c, "ps", "-o", "pid,args")).split("\n");
const helpers = async (c: Container) =>
	(await processes(c)).filter((p) => p.includes("helper.mjs"));

/** The foundation's modules the image's outbound is run once more with: outbound, and the TLS floor it takes. */
export const lookupModules = ["tls-options", "outbound"] as const;
/** Their configuration beside the kernel's: outbound reaching the app at `pair` alone, in plain http. */
export const lookupConfig = (pair: string) => ({
	outbound: { "allow-any-public": true, "plain-loopback": [pair], "plain-ipv4": [pair] },
});

/** The image's outbound run once more in the container: the status of the app's readiness at `localhost`, for IPv4 where it listens. */
const lookedUp = async (c: Container, port: string) =>
	(
		await inside(
			c,
			"node",
			"--input-type=module",
			"-e",
			`import { assemble, kernelConfig } from "@o3co/auth-provider-foundation/kernel";
import { outbound } from "@o3co/auth-provider-foundation/outbound";
${lookupModules.map((name, i) => `import m${i} from "@o3co/auth-provider-foundation/${name}/module";`).join("\n")}
const pair = "localhost:${port}";
const app = await assemble({ modules: [${lookupModules.map((_, i) => `m${i}`).join(", ")}], config: { ...kernelConfig(), ...${JSON.stringify(lookupConfig(`localhost:${port}`))} } });
const answer = await app.get(outbound).fetch("http://" + pair + "/readyz").then((a) => String(a.status), (e) => "failed: " + (e?.failure ?? e?.name));
await app.stop();
process.stdout.write(answer);`,
		)
	).trim();

/** The one port the image exposes. */
const portOf = async (image: string) =>
	Object.keys(
		JSON.parse(
			await docker(
				["image", "inspect", "--format", "{{json .Config.ExposedPorts}}", image],
				60_000,
			),
		),
	)[0]?.split("/")[0] ?? "";

/** The helpers scene, as `release-check`'s card tells it: limited, refused as measured, ended with its app. */
export async function helperScene(run: Booting, app: string, image: string): Promise<string> {
	// Room for the app and its helpers, and for one more process of outbound and its helpers.
	const constrained = ["--read-only", "--tmpfs", "/tmp", "--pids-limit", "128"];
	const port = await portOf(image);
	let running = 0;
	let reached = "";
	const ready = await run.booted(app, image, constrained, async (c) => {
		running = (await helpers(c)).length;
		reached = await lookedUp(c, port);
	});
	if (ready !== "ready" || running !== 2 || reached !== "200") {
		throw new Error(
			`read-only under a process limit: ${ready}, ${running} helpers, a lookup ${reached}`,
		);
	}

	const conf = join(app, "config", "in-process.conf");
	writeFileSync(conf, 'outbound { resolution = "in-process" }\n');
	const inProcess = [
		"-v",
		`${conf}:/app/config/in-process.conf:ro`,
		"-e",
		"APP_CONFIG=config/in-process.conf,config/local.conf,config/application.conf",
	];
	let taken = 0;
	const own = await run.booted(app, image, inProcess, async (c) => {
		taken = await pidsCurrent((path) => inside(c, "cat", path));
	});
	if (own !== "ready" || !(taken > 0)) throw new Error(`in-process: ${own}, ${taken} processes`);
	const refused = await run.booted(app, image, ["--pids-limit", String(taken)]);
	if (!refused.startsWith("refused: outbound.resolution:")) {
		throw new Error(`no room for a helper: ${refused}`);
	}

	let ended = false;
	await run.booted(app, image, [], async (c) => {
		// The app's own node, not the init (Tini) that started it, nor a helper.
		const main = (await processes(c)).find(
			(p) => /^\s*\d+\s+(\{[^}]*\}\s+)?node\s/.test(p) && !p.includes("helper.mjs"),
		);
		const pid = main?.trim().split(/\s+/)[0];
		if (pid === undefined) throw new Error("the app's process is not found");
		await inside(c, "kill", "-9", pid);
		ended = await c.until(async () => !(await c.state())?.running, 100, 10_000);
	});
	if (!ended) throw new Error("the container outlived its app's process");
	return `read-only and limited, resolving through its helpers; refused as measured (${taken}); ended with its app`;
}
