import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

/** Each jar in `dir`, by name, with its SHA-256, in name order. */
export function jarsIn(dir: string): { file: string; sha256: string }[] {
	return readdirSync(dir)
		.filter((f) => f.endsWith(".jar"))
		.sort()
		.map((file) => ({
			file,
			sha256: createHash("sha256")
				.update(readFileSync(join(dir, file)))
				.digest("hex"),
		}));
}

/** The pins as `sha256sum` writes them, so `shasum -a 256 -c` reads them too. */
export const pinsText = (jars: readonly { file: string; sha256: string }[]) =>
	jars.map((j) => `${j.sha256}  ${j.file}\n`).join("");

/** How the jars differ from their pins: one whose hash is not pinned, one pinned and missing, one not pinned. */
export function pinProblems(
	jars: readonly { file: string; sha256: string }[],
	pins: string,
): string[] {
	const pinned = new Map(
		pins
			.split("\n")
			.filter((l) => l.trim() !== "")
			.map((l) => {
				const [sha256 = "", file = ""] = l.split(/\s+/);
				return [file, sha256] as const;
			}),
	);
	const found = new Map(jars.map((j) => [j.file, j.sha256]));
	return [
		...jars.flatMap((j) => {
			const pin = pinned.get(j.file);
			if (pin === undefined) return [`${j.file}: not pinned`];
			return pin === j.sha256
				? []
				: [`${j.file}: its SHA-256 is ${j.sha256}, not the pinned ${pin}`];
		}),
		...[...pinned.keys()].filter((f) => !found.has(f)).map((f) => `${f}: pinned, and not there`),
	];
}
