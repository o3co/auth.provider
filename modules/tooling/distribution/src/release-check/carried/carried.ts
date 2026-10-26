/** What package managers an app's image holds, looked for in the image itself. */
import type { Container } from "../containers/container.ts";

/**
 * A shell script that prints each package manager an app's image still holds: on its PATH, or where
 * Node's image keeps the corepack and the yarn it bundles. The app runs node alone.
 */
const carriedScript = `for tool in corepack pnpm yarn yarnpkg; do command -v "$tool"; done; ls -d /usr/local/lib/node_modules/corepack /opt/yarn-v* 2>/dev/null; true`;

/** Each path `image`, run in `c`, holds a package manager at; none where it holds none. */
export async function carried(c: Container, image: string): Promise<string[]> {
	const found = await c.run(["--network=none", "--entrypoint", "sh", image, "-c", carriedScript]);
	return found
		.split("\n")
		.map((line) => line.trim())
		.filter((line) => line !== "");
}
