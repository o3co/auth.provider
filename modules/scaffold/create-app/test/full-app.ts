import { mkdir, mkdtemp, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { trialLayer } from "@mod/trial";
import { generate, type PatternPlan } from "../src/contract.ts";
import { workspacePackages } from "../src/project.ts";

/** The workspace these tests generate from, and its package directories by name. */
export const root = join(import.meta.dirname, "..", "..", "..", "..");
export const packageDirs = workspacePackages(root);

export type Tree = { [key: string]: unknown };
export const isTree = (value: unknown): value is Tree =>
	typeof value === "object" && value !== null && !Array.isArray(value);
/** Each leaf with its path: objects are walked into, lists and scalars are leaves. */
export const leaves = (value: Tree, path: string[] = []): [string[], unknown][] =>
	Object.entries(value).flatMap(([k, v]) =>
		isTree(v) ? leaves(v, [...path, k]) : [[[...path, k], v] as [string[], unknown]],
	);

/** The packages whose `./module` a generated app imports, in its order. */
export const importedModules = async (target: string) =>
	[
		...(await read(target, "src/main.ts")).matchAll(
			/from "(@[a-z0-9._~-]+\/[a-z0-9._~-]+)\/module"/g,
		),
	].map((m) => m[1]);

/** The full template generated into a new temporary directory, with these features added. */
export async function generated(add?: string[]): Promise<string> {
	const target = await mkdtemp(join(tmpdir(), "create-app-full-"));
	await generate({ target, template: "full", workspace: root, ...(add ? { add } : {}) });
	return target;
}

/** The pattern generated into a new temporary directory, with the operator's choice. */
export async function generatedPattern(
	template: string,
	choice: Omit<PatternPlan, "target" | "template" | "workspace"> = {},
): Promise<string> {
	const target = await mkdtemp(join(tmpdir(), `create-app-${template}-`));
	await generate({ target, template, workspace: root, ...choice });
	return target;
}

export const read = (target: string, path: string) => readFile(join(target, path), "utf8");

/** The app in `target` with what installing would link, without asking the registry. */
export async function linked(target: string): Promise<string> {
	const pkg = JSON.parse(await read(target, "package.json"));
	for (const [name, link] of Object.entries(pkg.dependencies) as [string, string][]) {
		const [scope, base] = name.split("/") as [string, string];
		await mkdir(join(target, "node_modules", scope), { recursive: true });
		await symlink(link.slice("link:".length), join(target, "node_modules", scope, base));
	}
	return target;
}

/** The full template, linked. */
export const installed = async () => linked(await generated());

/** Writes trial's local layer into the app, for this deployment, Redis and http port. */
export async function configured(
	target: string,
	settings: { deployment: "single" | "multi"; redisUrl: string; port?: number },
): Promise<void> {
	const layer = [
		`kernel.deployment = ${settings.deployment}`,
		...(settings.port ? [`http.port = ${settings.port}`] : []),
	].join("\n");
	const local = await trialLayer(target, { redisUrl: settings.redisUrl, layer });
	await writeFile(join(target, "config", "local.conf"), local);
}
