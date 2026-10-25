import { execFile } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);

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
export async function hostForSuite(): Promise<SuiteHost> {
	if (process.platform === "darwin") return { name: "host.docker.internal", listen: "127.0.0.1" };
	const { stdout } = await run("docker", [
		"network",
		"inspect",
		"bridge",
		"-f",
		"{{(index .IPAM.Config 0).Gateway}}",
	]);
	const gateway = stdout.trim();
	return { name: "host.docker.internal", listen: gateway, mapped: gateway };
}

/**
 * The compose file beside the suite's own: its store is in memory, never a directory of this
 * machine's (a run's store is thrown away, and Docker Desktop's shared directories can refuse its
 * writes); its server reaches this machine by name, mapped to an IPv4 address alone (`host-gateway`
 * adds an IPv6 one the suite's Java may pick and find no route to); its nginx answers with the
 * harness's certificate, which names the suite's host, so a client checking names can reach it.
 */
export const composeOverride = (
	host: SuiteHost,
	tls: { readonly cert: string; readonly key: string },
) => `services:
  mongodb:
    volumes:
      - type: tmpfs
        target: /data/db
  nginx:
    volumes:
      - type: bind
        source: ${tls.cert}
        target: /etc/ssl/certs/nginx-selfsigned.crt
        read_only: true
      - type: bind
        source: ${tls.key}
        target: /etc/ssl/private/nginx-selfsigned.key
        read_only: true
${
	host.mapped === undefined
		? ""
		: `  server:
    extra_hosts:
      - "${host.name}:${host.mapped}"
`
}`;

/**
 * The compose file's environment: the image tag pinned, and the suite's public origins as the
 * harness names them, never as the runner's environment has them (vitest sets `BASE_URL` to `/`
 * for Vite, which the compose file would take for the suite's origin).
 */
export const suiteEnv = (pin: SuitePin): NodeJS.ProcessEnv => ({
	...process.env,
	IMAGE_TAG: pin.tag,
	BASE_URL: suiteOrigin,
	BASE_MTLS_URL: "https://localhost.emobix.co.uk:8444",
});

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

/** A start's Compose project: one of its own, from its whole directory, as every start's ends alike. */
export const projectOf = (dir: string) =>
	`o3co-oidf-${createHash("sha256").update(dir).digest("hex").slice(0, 16)}`;

/**
 * The check of a server's identity that takes this certificate alone, by its fingerprint: the
 * suite's names `localhost`, not the host it is reached by, so its name is no check.
 */
export function pinnedTo(pem: string) {
	const pinned = new X509Certificate(pem).fingerprint256;
	return (_host: string, presented: { readonly fingerprint256: string }) =>
		presented.fingerprint256 === pinned
			? undefined
			: new Error("the suite answered with another certificate than the one first read");
}

/** A JSON GET at the suite, trusting the certificate it was first read with alone. */
export async function getJson(url: string, ca: string): Promise<{ status: number; body: unknown }> {
	const { request } = await import("node:https");
	const checkServerIdentity = pinnedTo(ca);
	return new Promise((resolve, reject) => {
		const req = request(url, { ca, checkServerIdentity, timeout: 30_000 }, (res) => {
			// An answer cut off midway is refused, never left pending.
			res.on("error", reject);
			res.on("aborted", () => reject(new Error(`the suite cut its answer to ${url} off`)));
			let text = "";
			res.on("data", (chunk) => {
				text += chunk;
			});
			res.on("end", () => {
				let body: unknown = text;
				try {
					body = JSON.parse(text);
				} catch {}
				resolve({ status: res.statusCode ?? 0, body });
			});
		});
		req.on("timeout", () => req.destroy(new Error(`the suite did not answer ${url}`)));
		req.on("error", reject);
		req.end();
	});
}

/**
 * Starts the suite at `pin` in `dir`: its source at the pinned commit (the compose file and the
 * scripts), a Python of its own for the scripts, and its containers under a project of their own.
 * Stopping keeps the server's log in `log` first, then takes the containers and their volumes down
 * and removes `dir`, however the start went.
 */
export async function startSuite(
	pin: SuitePin,
	dir: string,
	host: SuiteHost,
	log: string,
	/** The certificate its nginx answers with, as PEM: one naming `localhost.emobix.co.uk`. */
	tls: { readonly cert: string; readonly key: string },
): Promise<Suite> {
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
	const env = suiteEnv(pin);
	const stop = async () => {
		// Every container's state and log: a failed start is often one of them gone.
		const said = async (args: readonly string[]) =>
			(
				await run("docker", [...compose, ...args], { env, maxBuffer: 64 * 1024 * 1024 }).catch(
					() => ({ stdout: "" }),
				)
			).stdout;
		const states = await said(["ps", "--all", "--format", "{{.Service}} {{.State}} {{.Status}}"]);
		const logs = await said(["logs", "--no-color"]);
		await writeFile(log, `${states}\n${logs}`).catch(() => {});
		await run("docker", [...compose, "down", "--volumes", "--remove-orphans"], { env }).catch(
			() => {},
		);
		await rm(dir, { recursive: true, force: true });
	};
	try {
		await run("git", [
			"clone",
			"--quiet",
			"--depth",
			"1",
			"--branch",
			pin.tag,
			"https://gitlab.com/openid/conformance-suite.git",
			source,
		]);
		const { stdout: head } = await run("git", ["-C", source, "rev-parse", "HEAD"]);
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
		await run("python3", ["-m", "venv", venv]);
		await run(join(venv, "bin", "pip"), ["install", "--quiet", ...pin.python]);
		await run("docker", [...compose, "up", "--detach", "--quiet-pull"], { env });
		const deadline = Date.now() + readyWithinMs;
		// Only the harness's certificate is trusted, by its fingerprint: an nginx answering with its own fails.
		const ca = tls.cert;
		for (;;) {
			try {
				if ((await getJson(`${suiteOrigin}/api/plan?length=1`, ca)).status === 200) break;
			} catch {}
			if (Date.now() > deadline)
				throw new Error(`the suite did not answer within ${readyWithinMs / 1000}s`);
			await new Promise((resolve) => setTimeout(resolve, 2_000));
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
		await stop();
		throw error;
	}
}
