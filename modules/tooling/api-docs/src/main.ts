import { resolve } from "node:path";
import { buildVersion } from "./build.ts";
import { linkBuilt } from "./link.ts";
import { indexSite, versionDir } from "./site.ts";

const usage = [
	"api-docs link <bundles> <project>      the bundles built here, linked as a release installs them",
	"api-docs build <project> <site> <version>  a release's API into its minor's dir, and the site's index",
].join("\n");

const [command, ...rest] = process.argv.slice(2);
if (command === "link" && rest.length === 2) {
	const [bundles, project] = rest.map((p) => resolve(p)) as [string, string];
	linkBuilt({ bundles, repo: resolve(import.meta.dirname, "../../../.."), project });
	console.log(`api-docs: linked ${bundles} into ${project}`);
} else if (command === "build" && rest.length === 3) {
	const [project, site, version] = rest as [string, string, string];
	const out = resolve(site, versionDir(version));
	await buildVersion({ project: resolve(project), out, version });
	indexSite(resolve(site));
	console.log(`api-docs: ${version} at ${out}`);
} else {
	console.error(usage);
	process.exit(2);
}
