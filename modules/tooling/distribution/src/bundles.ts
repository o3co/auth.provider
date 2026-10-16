import { existsSync } from "node:fs";
import { join } from "node:path";
import { buildBundles } from "./build.ts";
import { readBundles } from "./contract.ts";
import { releaseOf } from "./workspace.ts";

const root = process.env.INIT_CWD ?? process.cwd();
const release = releaseOf(root);
if (!release) {
	console.error("bundles: the workspace's package.json states no version");
	process.exit(1);
}
const { built, problems } = buildBundles({
	bundles: readBundles(root),
	release,
	out: join(root, "dist", "bundles"),
	...(existsSync(join(root, "LICENSE")) ? { licenseFile: join(root, "LICENSE") } : {}),
});
for (const problem of problems) console.error(problem);
console.log(
	problems.length === 0 ? `bundles: ${built.length} built` : `bundles: ${problems.length}`,
);
process.exit(problems.length === 0 ? 0 : 1);
