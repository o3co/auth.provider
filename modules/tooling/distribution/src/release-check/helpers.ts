/** The resolver's helper processes in an app's image, run as a deployment constrains it. */
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { gone, pidsCurrent } from "./container.ts";
import { docker } from "./docker.ts";

/** The part of `images` a scene drives: booting the image with constraints, a look while ready. */
interface Booting {
	booted(
		app: string,
		image: string,
		constraints?: readonly string[],
		whileReady?: (container: string) => void,
	): Promise<string>;
}

const inside = (container: string, ...command: string[]) => docker(["exec", container, ...command]);
/** The command lines of the container's processes. */
const processes = (container: string) => inside(container, "ps", "-o", "pid,args").split("\n");
const helpers = (container: string) => processes(container).filter((p) => p.includes("helper.mjs"));
const isGone = (container: string) => gone(() => docker(["inspect", container]));

/** The image's outbound run once more in the container: the status of the app's readiness at `localhost`, for IPv4 where it listens. */
const lookedUp = (container: string, port: string) =>
	inside(
		container,
		"node",
		"--input-type=module",
		"-e",
		`import { assemble, kernelConfig } from "@o3co/auth-provider-foundation/kernel";
import { outbound } from "@o3co/auth-provider-foundation/outbound";
import outboundModule from "@o3co/auth-provider-foundation/outbound/module";
const pair = "localhost:${port}";
const app = await assemble({ modules: [outboundModule], config: { ...kernelConfig(), outbound: { "allow-any-public": true, "plain-loopback": [pair], "plain-ipv4": [pair] } } });
const answer = await app.get(outbound).fetch("http://" + pair + "/readyz").then((a) => String(a.status), (e) => "failed: " + (e?.failure ?? e?.name));
await app.stop();
process.stdout.write(answer);`,
	).trim();

/** The one port the image exposes. */
const portOf = (image: string) =>
	Object.keys(
		JSON.parse(docker(["image", "inspect", "--format", "{{json .Config.ExposedPorts}}", image])),
	)[0]?.split("/")[0] ?? "";

/**
 * Boots the image read-only, under a process limit and Docker's default seccomp profile, with its
 * two helpers running and a name resolved through them within those limits; measures what the app takes resolving in its own process, and refuses boot
 * under exactly that limit, as no helper can start; and ends the container, leaving nothing, once
 * the app's own process is killed.
 */
export async function helperScene(run: Booting, app: string, image: string): Promise<string> {
	// Room for the app and its helpers, and for one more process of outbound and its helpers.
	const constrained = ["--read-only", "--tmpfs", "/tmp", "--pids-limit", "128"];
	const port = portOf(image);
	let running = 0;
	let reached = "";
	const ready = await run.booted(app, image, constrained, (c) => {
		running = helpers(c).length;
		reached = lookedUp(c, port);
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
	const own = await run.booted(app, image, inProcess, (c) => {
		taken = pidsCurrent((path) => inside(c, "cat", path));
	});
	if (own !== "ready" || !(taken > 0)) throw new Error(`in-process: ${own}, ${taken} processes`);
	const refused = await run.booted(app, image, ["--pids-limit", String(taken)]);
	if (!refused.startsWith("refused: outbound.resolution:")) {
		throw new Error(`no room for a helper: ${refused}`);
	}

	let ended = false;
	await run.booted(app, image, [], (c) => {
		// The app's own node, not the init (Tini) that started it, nor a helper.
		const main = processes(c).find(
			(p) => /^\s*\d+\s+(\{[^}]*\}\s+)?node\s/.test(p) && !p.includes("helper.mjs"),
		);
		const pid = main?.trim().split(/\s+/)[0];
		if (pid === undefined) throw new Error("the app's process is not found");
		inside(c, "kill", "-9", pid);
		for (let waited = 0; waited < 10_000 && !ended; waited += 100) {
			ended = isGone(c);
			execFileSync("sleep", ["0.1"]);
		}
	});
	if (!ended) throw new Error("the container outlived its app's process");
	return `read-only and limited, resolving through its helpers; refused as measured (${taken}); ended with its app`;
}
