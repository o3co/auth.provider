import type { Started } from "./driver.ts";

/** A scene made of the parts of named areas; the base reads none of them. */
export interface AreaScene {
	readonly parts: Readonly<Record<string, unknown>>;
	/** The store can be made unreachable while the scene runs. */
	readonly storeFaults?: boolean;
	/** Whether the operator accepts a store that loses data on restart; accepted unless said otherwise. */
	readonly acceptVolatileStore?: boolean;
}

/** One area of the scenes, named once, with its part's shape. */
export interface Area<Part> {
	readonly name: string;
	/** This part, ready to go into a scene. */
	part(part: Part): readonly [string, Part];
	/** This area's part of a scene, if it has one. */
	in(scene: AreaScene): Part | undefined;
}

export function area<Part>(name: string): Area<Part> {
	return {
		name,
		part: (part) => [name, part] as const,
		in: (scene) => scene.parts[name] as Part | undefined,
	};
}

export function sceneOf(...parts: readonly (readonly [string, unknown])[]): AreaScene {
	return { parts: Object.fromEntries(parts) };
}

/** What one area's part asks of a composition of the new system. */
export interface NewPart {
	readonly modules?: readonly string[];
	/** Modules the scene is about the absence of; a pattern composing one cannot hold it. */
	readonly without?: readonly string[];
	/** Sections by name; two parts naming one section have their settings merged. */
	readonly config?: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
	/** Sections only where nothing decides them: a pattern's app takes its trial layer instead. */
	readonly fallback?: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
	/** Sections that hold only the scene's own keys: a pattern's app mixes no trial value into them. */
	readonly whole?: readonly string[];
	/** A store that may lose data on restart, or one on a server that can be paused. */
	readonly store?: "volatile" | "pausable";
	/** A configuration file's text, as an operator writes it: booted below the scene's sections. */
	readonly layer?: string;
}

type SetUp = (part: unknown, scene: AreaScene, modules: readonly string[]) => NewPart;
const newMappings = new Map<string, SetUp>();
type Adapt = (part: unknown, scene: AreaScene, modules: readonly string[]) => PatternPart;
const patternMappings = new Map<string, Adapt>();

/** How an area's part is set up on the new system composing `modules`, and on a pattern's app where that differs; said once. */
export function onNew<Part>(
	owner: Area<Part>,
	map: (part: Part, scene: AreaScene, modules: readonly string[]) => NewPart,
	onPattern?: (part: Part, scene: AreaScene, modules: readonly string[]) => PatternPart,
): void {
	newMappings.set(owner.name, map as SetUp);
	if (onPattern) patternMappings.set(owner.name, onPattern as Adapt);
}

function newPartOf(
	name: string,
	part: unknown,
	scene: AreaScene,
	modules: readonly string[],
): NewPart {
	const map = newMappings.get(name);
	if (!map) throw new Error(`no new-system set-up for the area ${name}`);
	return map(part, scene, modules);
}

/** Every part of the scene, set up as its area says for `modules`; a part no area set up is a mistake. */
export function newPartsOf(scene: AreaScene, modules: readonly string[]): NewPart[] {
	return Object.entries(scene.parts).map(([name, part]) => newPartOf(name, part, scene, modules));
}

/** A party a pattern's app reaches over plain http at `base`, started before the app and stopped after it. */
export interface Party {
	readonly base: string;
	/** Sections that point the app at it. */
	readonly config: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
	stop(): Promise<void>;
}

/** A part set up for a pattern's app, with any party it needs; or why the app's choice on an axis cannot hold it. */
export type PatternPart =
	| (NewPart & { readonly party?: () => Promise<Party> })
	| { readonly leaveOut: string };

/** Every part of the scene, set up for a pattern's app composing `modules`. */
export function patternPartsOf(scene: AreaScene, modules: readonly string[]): PatternPart[] {
	return Object.entries(scene.parts).map(([name, part]) => {
		const adapt = patternMappings.get(name);
		return adapt ? adapt(part, scene, modules) : newPartOf(name, part, scene, modules);
	});
}

/** A target the area scenes run against. */
export interface AreaDriver {
	start(scene: AreaScene): Promise<Started>;
	/** False when the target cannot be set up for this need at all. */
	can(need: string): boolean;
	/** True when the target answers this decided difference otherwise than the scenes expect. */
	differs(difference: string): boolean;
}

const drivers = new Map<string, AreaDriver>();

export function registerDriver(name: string, driver: AreaDriver): void {
	drivers.set(name, driver);
}

/** The target `CONFORMANCE_TARGET` names; the new system when it names none. */
export function areaTarget(): AreaDriver {
	const name = process.env.CONFORMANCE_TARGET ?? "new";
	const driver = drivers.get(name);
	if (!driver) throw new Error(`no driver registered for the target ${name}`);
	return driver;
}
