/** A listed app's project: the modules' entry and manifest, and `kernel`'s section alone as its configuration. */
import { kernelConfig } from "@mod/kernel";
import type { Packages } from "./packages.ts";
import {
	mainSource,
	manifestOf,
	resealSource,
	sealPackage,
	vacant,
	withKernel,
	writeProject,
} from "./project.ts";

/** Writes the app assembling `modules` from `packages` into an empty target. */
export async function writeListed(
	target: string,
	modules: readonly string[],
	packages: Packages,
): Promise<void> {
	await vacant(target);
	const seals = modules.includes(sealPackage);
	await writeProject(target, {
		"package.json": manifestOf(
			"node src/main.ts",
			packages.dependencies(withKernel(modules)),
			seals ? "node src/reseal.ts" : undefined,
		),
		"src/main.ts": await mainSource(modules, packages.importOf),
		...(seals ? { "src/reseal.ts": await resealSource(modules, packages.importOf) } : {}),
		"config/application.conf": `${JSON.stringify(kernelConfig(), null, "\t")}\n`,
		".gitignore": "node_modules/\nconfig/local*.conf\n",
	});
}
