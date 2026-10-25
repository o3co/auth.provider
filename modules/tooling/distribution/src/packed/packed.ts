/**
 * A packed tarball read for what it is: its name, version and integrity. Node's own modules alone,
 * as the job that publishes reads tarballs with it and must load nothing from outside.
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

/** A packed tarball's name, version and integrity, as npm records the integrity of what it is given. */
export interface Packed {
	readonly name: string;
	readonly version: string;
	readonly integrity: string;
}

/** The integrity npm gives a tarball: the SHA-512 of its bytes, in base64. */
export const integrityOf = (bytes: Uint8Array) =>
	`sha512-${createHash("sha512").update(bytes).digest("base64")}`;

/** A tarball as packed: the name and version its manifest states, and the integrity of its bytes. */
export function packedOf(tarball: string): Packed {
	const manifest = JSON.parse(
		execFileSync("tar", ["-xzOf", tarball, "package/package.json"], { encoding: "utf8" }),
	) as { name?: unknown; version?: unknown };
	return {
		name: String(manifest.name),
		version: String(manifest.version),
		integrity: integrityOf(readFileSync(tarball)),
	};
}
