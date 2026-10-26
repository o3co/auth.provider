/** The registry asked for each package at its version, and the tarballs it holds taken, each held to the integrity it gave. */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { integrityOf, tarballFileOf } from "../packed/packed.ts";
import { type Lookup, lookupOf } from "../release/published.ts";
import type { Unit } from "./plan.ts";

type Versioned = Unit & { readonly version: string };

/** How a command is run: its status and what it wrote on standard error. */
export type Run = (
	command: string,
	args: readonly string[],
) => { readonly status: number | null; readonly stderr?: string };
const npm: Run = (command, args) =>
	spawnSync(command, args, { encoding: "utf8", timeout: 120_000 });

/** What the registry answers for each package at its version: there with its integrity, not there, or no answer read. */
export function lookedUp(units: readonly Versioned[]): Map<string, Lookup> {
	return new Map(
		units.map((u) => {
			const answer = spawnSync(
				"npm",
				["view", `${u.name}@${u.version}`, "dist.integrity", "--json"],
				{
					encoding: "utf8",
					timeout: 60_000,
				},
			);
			return [
				u.name,
				lookupOf({
					status: answer.status ?? 1,
					stdout: answer.stdout ?? "",
					stderr: answer.stderr ?? "",
				}),
			];
		}),
	);
}

/**
 * Each package taken from the registry into `into` (`npm pack` of its name and version, no script
 * run), by its directory; one whose bytes are not of the integrity the registry gave is refused.
 */
export function takenFromRegistry(
	units: readonly (Versioned & { readonly integrity: string })[],
	into: string,
	run: Run = npm,
): { readonly given: Map<string, string> } | { readonly problems: string[] } {
	mkdirSync(into, { recursive: true });
	const problems: string[] = [];
	const given = new Map<string, string>();
	for (const u of units) {
		const got = run("npm", [
			"pack",
			`${u.name}@${u.version}`,
			"--pack-destination",
			into,
			"--ignore-scripts",
		]);
		const file = join(into, tarballFileOf(u.name, u.version));
		if (got.status !== 0 || !existsSync(file)) {
			problems.push(
				`${u.name}@${u.version}: not taken from the registry (${(got.stderr ?? "").trim()})`,
			);
		} else if (integrityOf(readFileSync(file)) !== u.integrity) {
			problems.push(
				`${u.name}@${u.version}: the registry's tarball is not of the integrity it gave`,
			);
		} else given.set(u.dir, file);
	}
	return problems.length > 0 ? { problems } : { given };
}
