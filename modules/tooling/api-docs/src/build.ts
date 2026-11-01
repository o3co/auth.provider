import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Application } from "typedoc";
import { entriesOf } from "./entries.ts";

/**
 * Builds one version's API from the bundles a project holds in its `node_modules` (installed, or
 * linked): one module per member's contract, named and imported by its public name.
 */
export async function buildVersion(options: {
	readonly project: string;
	readonly out: string;
	readonly version: string;
}): Promise<void> {
	const { project, out, version } = options;
	const work = join(project, ".api-docs");
	rmSync(work, { recursive: true, force: true });
	mkdirSync(join(work, "entries"), { recursive: true });
	const entryPoints = entriesOf(project).map((name, i) => {
		const file = join(work, "entries", `${i}.ts`);
		// The tag names the module as an app imports it, not by the file it is read from.
		writeFileSync(file, `/**\n * @module ${name}\n */\nexport * from "${name}";\n`);
		return file;
	});
	if (entryPoints.length === 0) throw new Error(`no bundle's contract in ${project}`);
	writeFileSync(
		join(work, "tsconfig.json"),
		JSON.stringify({
			compilerOptions: {
				target: "es2024",
				module: "nodenext",
				moduleResolution: "nodenext",
				strict: true,
				skipLibCheck: true,
				noEmit: true,
			},
			include: ["entries/*.ts"],
		}),
	);
	const app = await Application.bootstrapWithPlugins({
		entryPoints,
		entryPointStrategy: "resolve",
		tsconfig: join(work, "tsconfig.json"),
		name: `auth-provider API ${version}`,
		readme: "none",
		excludePrivate: true,
		excludeInternal: true,
		plugin: [],
	});
	const converted = await app.convert();
	if (!converted || app.logger.hasErrors()) throw new Error("the API could not be read");
	await app.generateDocs(converted, out);
	if (app.logger.hasErrors()) throw new Error("the API's site could not be written");
}
