import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

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
