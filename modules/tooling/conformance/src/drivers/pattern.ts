import { appendFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { optIns } from "@mod/combinations";
import { type PatternSummary, type Plan, patterns } from "@mod/create-app";
import { type AreaDriver, type AreaScene, type PatternPart, patternPartsOf } from "../areas.ts";
import { full, fullWithOptIns } from "../patterns/patterns.ts";
import { leaveOut } from "../skip.ts";
import { generated, sectionsOf, started, stores, workspace } from "./app.ts";

/** A pattern's file may name modules its conformance run adds. */
type Added = PatternSummary & { readonly conformanceAdd?: readonly string[] };

/** The word for a scene left out because the pattern's app cannot hold it. */
export const notInPattern = "not-in-pattern";

/** Why an app cannot hold a scene: it lacks a module the scene needs, composes what it is about the absence of, or chose an alternative, its Store among them. */
export interface Misfit {
	readonly kind: "lacking" | "absence" | "alternative";
	readonly reason: string;
}

/** Why the scene does not fit an app composing `modules`, or nothing where it fits. */
export function misfit(
	adapted: readonly PatternPart[],
	scene: AreaScene,
	modules: readonly string[],
): Misfit | undefined {
	const parts = adapted.flatMap((p) => ("leaveOut" in p ? [] : [p]));
	const lacking = (reason: string) => ({ kind: "lacking", reason }) as const;
	const chose = (reason: string) => ({ kind: "alternative", reason }) as const;
	const asked = parts.flatMap((p) => p.modules ?? []);
	const absent = asked.filter((m, i) => !modules.includes(m) && asked.indexOf(m) === i);
	if (absent.length > 0) return lacking(`lacks ${absent.join(", ")}`);
	const present = parts.flatMap((p) => p.without ?? []).filter((m) => modules.includes(m));
	if (present.length > 0) {
		return { kind: "absence", reason: `composes ${[...new Set(present)].join(", ")}` };
	}
	const pausable = modules.includes(stores.pausable);
	const pauses = scene.storeFaults || parts.some((p) => p.store === "pausable");
	if (pauses && !pausable) return chose("pauses the Store");
	if (scene.acceptVolatileStore === false && pausable) return chose("refuses a volatile Store");
	const chosen = adapted.flatMap((p) => ("leaveOut" in p ? [p.leaveOut] : []));
	return chosen[0] === undefined ? undefined : chose(chosen[0]);
}

/** How the pattern's app is generated, with the modules its file asks its conformance run to add. */
export function planOf(
	name: string,
	summaries: readonly PatternSummary[],
): (target: string) => Plan {
	if (name === full) return (target) => ({ target, template: full, workspace });
	if (name === fullWithOptIns)
		return (target) => ({ target, template: full, add: optIns(), workspace });
	const summary = summaries.find((p) => p.name === name) as Added | undefined;
	const add = summary?.conformanceAdd ?? [];
	// The audit events go to a receiver, which scenes read.
	const axes = { "@mod/audit": "@mod/audit-http" };
	return (target) => ({ target, template: name, axes, ...(add.length ? { add } : {}), workspace });
}

async function composedBy(dir: string): Promise<string[]> {
	const manifest = JSON.parse(await readFile(join(dir, "package.json"), "utf8"));
	return Object.keys(manifest.dependencies ?? {});
}

/** Adds the scene left out to the file the run names, for its count. */
function record(reason: string): void {
	const file = process.env.CONFORMANCE_NOT_IN_PATTERN_FILE;
	if (file) appendFileSync(file, `${reason}\n`);
}

/** One pattern's app, generated once; a scene it cannot hold is left out, or, lacking, fails with every opt-in. */
export function patternDriver(name: string): AreaDriver {
	let app: Promise<{ dir: string; modules: string[] }> | undefined;
	const appOf = () => {
		app ??= generated(name, planOf(name, patterns())).then(async (dir) => ({
			dir,
			modules: await composedBy(dir),
		}));
		return app;
	};
	return {
		can: () => true,
		differs: () => false,
		async start(scene, options) {
			const { dir, modules } = await appOf();
			const adapted = patternPartsOf(scene, modules);
			const unfit = misfit(adapted, scene, modules);
			if (unfit !== undefined) {
				const said = `${notInPattern}: ${unfit.reason}`;
				record(unfit.reason);
				if (name === fullWithOptIns && unfit.kind === "lacking")
					throw new Error(`${name}: ${said}`);
				leaveOut(said);
			}
			const parts = adapted.flatMap((p) => ("leaveOut" in p ? [] : [p]));
			const parties = await Promise.all(parts.flatMap((p) => (p.party ? [p.party()] : [])));
			const store = modules.includes(stores.pausable) ? "pausable" : "volatile";
			const config = sectionsOf([...parts, ...parties], false);
			// The issuer must be at the deployment's public origin; a scene that moves the origin moves it.
			const origin = config.http?.["public-origin"];
			if (typeof origin === "string" && !config.issuer && modules.includes("@mod/issuer")) {
				config.issuer = { url: origin };
			}
			// The pattern's app reads what a deployment would give it: trial's layer.
			const leave = [...new Set(parts.flatMap((p) => p.whole ?? []))];
			// The app's mail goes to a fake relay, unless the scene names its own.
			const smtp = modules.includes("@mod/mail-smtp") && !config["mail-smtp"];
			const layers = parts.flatMap((p) => (p.layer === undefined ? [] : [p.layer]));
			return started(dir, config, scene, store, { leave, parties, smtp }, layers, options);
		},
	};
}
