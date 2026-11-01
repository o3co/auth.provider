import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";

/** The legacy release the scenes start. */
export const legacyVersion = "0.17.0";

/** The commit of that release (the tag `v0.17.0` points at it), held here so no moved tag can stand in for it. */
export const legacyCommit = "5708b53e2843db65b2a4b2d1de025776be5f6ceb";

/** The commit to build: `LEGACY_COMMIT` where set (a full sha, for trying another by hand), else `legacyCommit`. */
export function legacyCommitOf(
	env: Readonly<Record<string, string | undefined>> = process.env,
): string {
	const commit = env.LEGACY_COMMIT || legacyCommit;
	if (!/^[0-9a-f]{40}$/.test(commit)) {
		throw new Error(`LEGACY_COMMIT must be a full commit sha, not ${JSON.stringify(commit)}`);
	}
	return commit;
}

/**
 * Where the legacy build is kept: `LEGACY_DIR`, else the user's cache (`XDG_CACHE_HOME`, or
 * `~/.cache` when that is unset, empty or relative), so the OS clearing its temp dir loses nothing.
 */
export function legacyDir(
	env: Readonly<Record<string, string | undefined>> = process.env,
	home = homedir(),
): string {
	if (env.LEGACY_DIR) return env.LEGACY_DIR;
	const xdg = env.XDG_CACHE_HOME;
	const cache = xdg && isAbsolute(xdg) ? xdg : join(home, ".cache");
	return join(cache, "auth-provider", `legacy-${legacyVersion}`);
}
