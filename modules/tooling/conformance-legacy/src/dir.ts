import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";

/** The legacy release the scenes start. */
export const legacyVersion = "0.17.0";

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
