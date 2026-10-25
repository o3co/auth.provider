import { needed } from "@mod/combinations";
import { type AreaScene, newPartsOf, registerDriver, type StartOptions } from "../areas.ts";
import { generated, type StoreKind, sectionsOf, started, stores, workspace } from "./app.ts";
import { patternDriver } from "./pattern.ts";

/** The parts' modules in the order first named, with what they need to run, then the sections each part gives for them. */
export function composition(scene: AreaScene) {
	const parts = newPartsOf(scene, []);
	const modules = ["@mod/http"];
	for (const part of parts) {
		for (const name of part.modules ?? []) if (!modules.includes(name)) modules.push(name);
	}
	// Every scene's events go to the audit sink, whatever its areas compose.
	for (const name of ["@mod/audit", "@mod/audit-http", "@mod/outbound"]) {
		if (!modules.includes(name)) modules.push(name);
	}
	const marks = parts.map((p) => p.store);
	const store: StoreKind | undefined =
		scene.storeFaults || marks.includes("pausable")
			? "pausable"
			: marks.includes("volatile")
				? "volatile"
				: undefined;
	if (store) modules.push(stores[store]);
	const composed = needed(modules);
	// A module stands for itself, or for the default adapter composed in its owner's place.
	const standIn = (m: string) => needed([m])[0] ?? m;
	const absent = parts.flatMap((p) => p.without ?? []).filter((m) => composed.includes(standIn(m)));
	if (absent.length > 0) throw new Error(`the scene is about the absence of ${absent.join(", ")}`);
	const set = newPartsOf(scene, composed);
	const layers = set.flatMap((p) => (p.layer === undefined ? [] : [p.layer]));
	const config = sectionsOf(set);
	// The generated configuration holds no value: one instance, unless a part says otherwise.
	config.kernel = { deployment: "single", ...config.kernel };
	return { modules: composed, config, layers, store };
}

/** The new system, composed of the modules each area's part asks for. */
const composedDriver = {
	can: () => true,
	differs: () => false,
	async start(scene: AreaScene, options?: StartOptions) {
		const { modules, config, layers, store } = composition(scene);
		const dir = await generated(modules.join(","), (target) => ({ target, modules, workspace }));
		return started(dir, config, scene, store, undefined, layers, options);
	},
};

const pattern = process.env.CONFORMANCE_PATTERN;
registerDriver("new", pattern ? patternDriver(pattern) : composedDriver);
