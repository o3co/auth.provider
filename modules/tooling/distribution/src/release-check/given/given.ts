/** Which tarballs the release check holds to: those it is given, as the release will publish them, or those it packs. */
import { readdirSync } from "node:fs";
import { join, resolve } from "node:path";

/**
 * The tarballs in the directory named, every `.tgz` in it, so the check tests the very bytes the
 * release publishes; named none, those `pack` packs into the scratch directory. A directory named
 * with no tarball in it is refused, never read as a release of nothing.
 */
export function tarballsToCheck(
	given: string | undefined,
	pack: (
		into: string,
	) => { readonly tarballs: readonly string[] } | { readonly problems: readonly string[] },
	scratch: string,
):
	| { readonly dir: string; readonly tarballs: readonly string[] }
	| { readonly problems: readonly string[] } {
	if (given === undefined) {
		const dir = join(scratch, "tarballs");
		const packed = pack(dir);
		return "problems" in packed ? packed : { dir, tarballs: packed.tarballs };
	}
	const dir = resolve(given);
	const tarballs = readdirSync(dir)
		.filter((file) => file.endsWith(".tgz"))
		.sort()
		.map((file) => join(dir, file));
	return tarballs.length === 0
		? { problems: [`${dir}: holds no tarball to check`] }
		: { dir, tarballs };
}
