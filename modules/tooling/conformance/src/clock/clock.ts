import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";

/** The libfaketime a process on a moved clock preloads, by its Alpine package version. */
export const libfaketime = "libfaketime=0.9.10-r3";

/** An Alpine image given, with libfaketime added: built once, its tag a hash of how it is built. */
export function clockImage(base: string): string {
	const recipe = `FROM ${base}\nRUN apk add --no-cache ${libfaketime}\n`;
	const tag = `conformance-clock:${createHash("sha256").update(recipe).digest("hex").slice(0, 16)}`;
	try {
		execFileSync("docker", ["image", "inspect", tag], { stdio: "ignore" });
	} catch {
		execFileSync("docker", ["build", "-q", "-t", tag, "-"], {
			input: recipe,
			stdio: ["pipe", "ignore", "inherit"],
		});
	}
	return tag;
}

/** The environment that runs a process on a clock moved by `offset`, such as `+2h`, its monotonic clock left alone. */
export const faketimeEnv = (offset: string) => [
	"-e",
	"LD_PRELOAD=/usr/lib/faketime/libfaketime.so.1",
	"-e",
	`FAKETIME=${offset}`,
	"-e",
	"FAKETIME_DONT_FAKE_MONOTONIC=1",
];

/**
 * The Node an app on a moved clock is probed in: Debian (glibc), as a Linux runner's, by digest.
 * musl's (Alpine's) Node is not moved by libfaketime, nor is Node by its single-threaded library.
 */
export const appClockBase =
	"node:24-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205";
/** Debian's libfaketime by version, whose thread-safe library (`libfaketimeMT`) moves a Node process. */
export const appLibfaketime = "libfaketime=0.9.10-2.1";

/** `appClockBase` with `appLibfaketime` added: built once, its tag a hash of how it is built. */
export function appClockImage(): string {
	const recipe = `FROM ${appClockBase}\nRUN apt-get update -qq && apt-get install -y -qq --no-install-recommends ${appLibfaketime} && rm -rf /var/lib/apt/lists/*\n`;
	const tag = `conformance-app-clock:${createHash("sha256").update(recipe).digest("hex").slice(0, 16)}`;
	try {
		execFileSync("docker", ["image", "inspect", tag], { stdio: "ignore" });
	} catch {
		execFileSync("docker", ["build", "-q", "-t", tag, "-"], {
			input: recipe,
			stdio: ["pipe", "ignore", "inherit"],
		});
	}
	return tag;
}

/** Where an image holds the thread-safe libfaketime, its directory named by its architecture. */
export function appLibfaketimeIn(image: string): string {
	return execFileSync("docker", [
		"run",
		"--rm",
		image,
		"sh",
		"-c",
		"ls /usr/lib/*/faketime/libfaketimeMT.so.1",
	])
		.toString()
		.trim();
}

/** Where this host holds the thread-safe libfaketime: `CONFORMANCE_FAKETIME_LIB`, else Debian's place on Linux; none elsewhere. */
export function hostLibfaketime(): string | undefined {
	const named = process.env.CONFORMANCE_FAKETIME_LIB;
	if (named) return existsSync(named) ? named : undefined;
	if (process.platform !== "linux") return undefined;
	const dir = "/usr/lib";
	for (const arch of readdirSync(dir)) {
		const at = join(dir, arch, "faketime", "libfaketimeMT.so.1");
		if (existsSync(at)) return at;
	}
	return undefined;
}

/** The environment that runs an app on a clock moved by `offset`, such as `+2h`, by `library`; its monotonic clock left alone. */
export const appClockEnv = (offset: string, library: string): Readonly<Record<string, string>> => ({
	LD_PRELOAD: library,
	FAKETIME: offset,
	FAKETIME_DONT_FAKE_MONOTONIC: "1",
});
