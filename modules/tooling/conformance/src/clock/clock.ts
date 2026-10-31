import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { dockerSync } from "../docker/docker.ts";

/** The libfaketime a process on a moved clock preloads, by its Alpine package version. */
export const libfaketime = "libfaketime=0.9.10-r3";

/** An Alpine image given, with libfaketime added: built once, its tag a hash of how it is built. */
export function clockImage(base: string): string {
	const recipe = `FROM ${base}\nRUN apk add --no-cache ${libfaketime}\n`;
	const tag = `conformance-clock:${createHash("sha256").update(recipe).digest("hex").slice(0, 16)}`;
	try {
		dockerSync("control", ["image", "inspect", tag], { stdio: "ignore" });
	} catch {
		dockerSync("build", ["build", "-q", "-t", tag, "-"], {
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
const appClockBase =
	"node:24-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205";
/** Debian's libfaketime by version, whose thread-safe library (`libfaketimeMT`) moves a Node process. */
const appLibfaketime = "libfaketime=0.9.10-2.1";

/** `appClockBase` with `appLibfaketime` added: built once, its tag a hash of how it is built. */
export function appClockImage(): string {
	const recipe = `FROM ${appClockBase}\nRUN apt-get update -qq && apt-get install -y -qq --no-install-recommends ${appLibfaketime} && rm -rf /var/lib/apt/lists/*\n`;
	const tag = `conformance-app-clock:${createHash("sha256").update(recipe).digest("hex").slice(0, 16)}`;
	try {
		dockerSync("control", ["image", "inspect", tag], { stdio: "ignore" });
	} catch {
		dockerSync("build", ["build", "-q", "-t", tag, "-"], {
			input: recipe,
			stdio: ["pipe", "ignore", "inherit"],
		});
	}
	return tag;
}

/** Where an image holds the thread-safe libfaketime, its directory named by its architecture. */
export function appLibfaketimeIn(image: string): string {
	return dockerSync("run", [
		"run",
		"--rm",
		image,
		"sh",
		"-c",
		"ls /usr/lib/*/faketime/libfaketimeMT.so.1",
	]).trim();
}

/** Each library probed, and whether it moved a Node process's clock: probed once per path. */
const probed = new Map<string, boolean>();

/**
 * Whether `library` moves this Node's clock: a Node started on it a day ahead says a time a day ahead.
 * A file being there is not enough: on musl, on macOS, or by the library that is not thread-safe,
 * Node's clock stays where it is.
 */
function moves(library: string): boolean {
	const known = probed.get(library);
	if (known !== undefined) return known;
	const before = Date.now();
	const answer = spawnSync(process.execPath, ["-e", "process.stdout.write(String(Date.now()))"], {
		encoding: "utf8",
		env: { PATH: process.env.PATH ?? "", ...appClockEnv("+1d", library) },
		timeout: 10_000,
	});
	const told =
		answer.status === 0 && answer.error === undefined ? Number(answer.stdout) : Number.NaN;
	const moved = told - before > 23 * 3_600_000;
	probed.set(library, moved);
	return moved;
}

/**
 * Where this host holds a thread-safe libfaketime that moves Node's clock: `CONFORMANCE_FAKETIME_LIB`,
 * else Debian's place on Linux; none where there is none, or where the one there moves no clock.
 */
export function hostLibfaketime(): string | undefined {
	const named = process.env.CONFORMANCE_FAKETIME_LIB;
	if (named) return existsSync(named) && moves(named) ? named : undefined;
	if (process.platform !== "linux") return undefined;
	const dir = "/usr/lib";
	for (const arch of readdirSync(dir)) {
		const at = join(dir, arch, "faketime", "libfaketimeMT.so.1");
		if (existsSync(at) && moves(at)) return at;
	}
	return undefined;
}

/** The environment that runs an app on a clock moved by `offset`, such as `+2h`, by `library`; its monotonic clock left alone. */
export const appClockEnv = (offset: string, library: string): Readonly<Record<string, string>> => ({
	LD_PRELOAD: library,
	FAKETIME: offset,
	FAKETIME_DONT_FAKE_MONOTONIC: "1",
});
