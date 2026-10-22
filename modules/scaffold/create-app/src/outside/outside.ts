import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { isAbsolute, join, relative } from "node:path";
import { namesPackages, type OutsideRecord, outsideLock, type Registries } from "@mod/app-output";
import type { Declaration } from "@mod/combinations";
import semver from "semver";
import { loadsSubpath } from "../exported/contract.ts";

/** What the release is, that an outside package is held to. */
export interface Release {
	/** The version every bundle of the release has. */
	readonly version: string;
	/** The zod every app depends on. */
	readonly zod: string;
	/** The bundle a module of the release ships in; none for any other name. */
	readonly bundleOf: (module: string) => string | undefined;
}

/** A package outside the release, as read from where pnpm installed it. */
export interface Outside {
	readonly declaration: Declaration;
	readonly record: OutsideRecord;
	/** Its section's example, its card and its section defaults, where it ships them. */
	readonly fragment?: string;
	readonly card?: string;
	readonly references?: string;
}

/** What was read from a project: the packages, and the registries it installs from. */
export interface Read {
	readonly outside: readonly Outside[];
	readonly registries: Registries;
}

/** The files of a package read, each at most this long; any other is never read. */
const fileBytes = 64 * 1024;
const files = ["package.json", "config.example", "README.md", "reference.conf"] as const;

/** The kinds a package outside the release may declare, and the fields its declaration may hold. */
const kinds = ["feature", "adapter", "wiring"];
const fields = new Set([
	"format",
	"kind",
	"needs",
	"optIn",
	"replaces",
	"adapts",
	"default",
	"wires",
	"joins",
]);
const installScripts = ["preinstall", "install", "postinstall"];

/** The release's own packages and zod: one copy each, the app's, so an outside package takes them as peers. */
const releaseScopes = ["@o3co/", "@mod/"];
const heldByApp = (name: string) => name === "zod" || name.startsWith("@o3co/auth-provider-");

type Json = Record<string, unknown>;
const isObject = (value: unknown): value is Json =>
	value !== null && typeof value === "object" && !Array.isArray(value);
const isName = (value: unknown): value is string => typeof value === "string" && value !== "";
const isNames = (value: unknown): value is string[] =>
	Array.isArray(value) && value.length > 0 && value.every(isName);
/** A manifest's map of names to text (dependencies, peers), its own keys alone. */
const rangesOf = (value: unknown): Record<string, string> =>
	isObject(value)
		? Object.fromEntries(Object.keys(value).map((key) => [key, String(value[key])]))
		: {};

/** Why a file of the package cannot be read: a link, no file, or over its bound. */
function readIn(dir: string, file: string): { text?: string; refusal?: string } {
	const path = join(dir, file);
	let stat: ReturnType<typeof lstatSync>;
	try {
		stat = lstatSync(path);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return {};
		throw error;
	}
	if (!stat.isFile()) return { refusal: `${file} is not a file` };
	if (stat.size > fileBytes) return { refusal: `${file} is over ${fileBytes} bytes` };
	return { text: readFileSync(path, "utf8") };
}

/** The directory pnpm installed `name` in, refused where it lies outside the project's node_modules. */
function installedIn(project: string, name: string): string {
	let base: string;
	let dir: string;
	try {
		base = realpathSync(join(project, "node_modules"));
		dir = realpathSync(join(project, "node_modules", name));
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
		throw new Error(`${name}: not installed in the project's node_modules`);
	}
	const within = relative(base, dir);
	if (within === "" || within.startsWith("..") || isAbsolute(within)) {
		throw new Error(`${name}: lies outside the project's node_modules`);
	}
	return dir;
}

/** The declaration in a manifest's `authProvider`, in the words composing reads, or why not. */
function declarationOf(
	name: string,
	stated: unknown,
): { declaration?: Declaration; refusals: string[] } {
	if (!isObject(stated)) return { refusals: ["declares no authProvider"] };
	if (stated.format !== 1)
		return { refusals: [`authProvider format ${String(stated.format)}, where 1 is read`] };
	const refusals = Object.keys(stated)
		.filter((key) => !fields.has(key))
		.map((key) => `authProvider holds ${key}, which it does not read`);
	const kind = stated.kind;
	if (typeof kind !== "string" || !kinds.includes(kind)) {
		return {
			refusals: [
				...refusals,
				`authProvider kind ${String(kind)} is not one of ${kinds.join(", ")}`,
			],
		};
	}
	const needs = stated.needs === undefined ? [] : stated.needs;
	if (!Array.isArray(needs) || !needs.every(isName))
		refusals.push("authProvider needs is not a list of names");
	for (const key of ["optIn", "default"] as const) {
		if (stated[key] !== undefined && stated[key] !== true)
			refusals.push(`authProvider ${key} is not true`);
	}
	for (const key of ["replaces", "adapts", "wires"] as const) {
		if (stated[key] !== undefined && !isName(stated[key]))
			refusals.push(`authProvider ${key} is not a name`);
	}
	if (stated.joins !== undefined && !isNames(stated.joins))
		refusals.push("authProvider joins is not a list of names");
	if (refusals.length > 0) return { refusals };
	const optional = <K extends keyof Declaration>(key: K) =>
		stated[key] === undefined ? {} : { [key]: stated[key] as Declaration[K] };
	return {
		declaration: {
			name,
			kind,
			needs: needs as string[],
			...optional("optIn"),
			...optional("replaces"),
			...optional("adapts"),
			...optional("default"),
			...optional("wires"),
			...optional("joins"),
		},
		refusals: [],
	};
}

/** Why a manifest's dependencies would bring a second copy of the release or of zod, or miss the app's. */
function copyRefusals(manifest: Json, declaration: Declaration, release: Release): string[] {
	const dependencies = rangesOf(manifest.dependencies);
	const optional = rangesOf(manifest.optionalDependencies);
	const peers = rangesOf(manifest.peerDependencies);
	const meta = isObject(manifest.peerDependenciesMeta) ? manifest.peerDependenciesMeta : {};
	const refusals: string[] = [];
	for (const dep of [...Object.keys(dependencies), ...Object.keys(optional)].filter(heldByApp)) {
		refusals.push(`depends on ${dep} itself, where it is a peer`);
	}
	const bundled = manifest.bundleDependencies ?? manifest.bundledDependencies;
	const bundles =
		bundled === true
			? Object.keys(dependencies)
			: Array.isArray(bundled)
				? bundled.map(String)
				: [];
	for (const dep of bundles.filter(heldByApp)) refusals.push(`bundles ${dep}`);
	// Each map on its own: merged, a peer of one name would hide a dependency's alias of it.
	for (const map of [dependencies, optional, peers]) {
		for (const [dep, spec] of Object.entries(map)) {
			const aliased = /^npm:(@?[^@]+)/.exec(spec)?.[1];
			if (aliased !== undefined && heldByApp(aliased))
				refusals.push(`${dep} is an alias of ${aliased}`);
		}
	}
	for (const [peer, range] of Object.entries(peers).filter(([peer]) => heldByApp(peer))) {
		if (isObject(meta[peer]) && (meta[peer] as Json).optional === true)
			refusals.push(`its peer ${peer} is optional`);
		const [want, whose] =
			peer === "zod" ? [release.zod, "the app's"] : [release.version, "the release's"];
		if (!semver.satisfies(want, range, { includePrerelease: true })) {
			refusals.push(`its peer ${peer} is ${range}, without ${whose} ${want}`);
		}
	}
	if (peers.zod === undefined) refusals.push("zod is not its peer");
	for (const need of declaration.needs) {
		const bundle = release.bundleOf(need);
		if (bundle !== undefined && peers[bundle] === undefined) {
			refusals.push(`needs ${need}, whose bundle ${bundle} is not its peer`);
		}
	}
	return refusals;
}

/** How pnpm is asked for a setting: the command, and how long it may take. */
export interface Asking {
	readonly pnpm?: string;
	readonly timeoutMs?: number;
}

/** The most pnpm may answer with, for one setting. */
const answerBytes = 64 * 1024;

/**
 * A setting of pnpm's in the project, as it reads its own and the operator's configuration; none
 * where unset. What pnpm says besides its answer is never passed on: a setting may hold a secret.
 */
function configIn(project: string, key: string, asking: Asking): string | undefined {
	const timeout = asking.timeoutMs ?? 10_000;
	let value: string;
	try {
		value = execFileSync(asking.pnpm ?? "pnpm", ["config", "get", key], {
			cwd: project,
			encoding: "utf8",
			timeout,
			maxBuffer: answerBytes,
			stdio: ["ignore", "pipe", "pipe"],
		}).trim();
	} catch (error) {
		// Told by its code alone: an answer over the bound and a timeout both end the child the same way.
		const { code } = error as NodeJS.ErrnoException;
		const why =
			code === "ENOENT"
				? "pnpm is not found"
				: code === "ENOBUFS"
					? `pnpm answered over ${answerBytes} bytes`
					: code === "ETIMEDOUT"
						? `pnpm did not answer within ${timeout} ms`
						: "pnpm failed";
		throw new Error(`the project's ${key} could not be read: ${why}`);
	}
	return value === "" || value === "undefined" ? undefined : value;
}

/** The origin of a registry's address, refused where it is no http address; the address itself is never told, for it may hold a secret. */
function originOf(setting: string, address: string): string {
	try {
		const url = new URL(address);
		if (url.protocol === "https:" || url.protocol === "http:") return url.origin;
	} catch {}
	throw new Error(`the project's ${setting} is not an http address`);
}

/** The registries the project installs from: its default, and the scope of each name read and the release's. */
function registriesIn(project: string, names: readonly string[], asking: Asking): Registries {
	const scopes = [
		...new Set([
			"@o3co",
			...names.filter((n) => n.startsWith("@")).map((n) => n.slice(0, n.indexOf("/"))),
		]),
	].sort();
	const own = scopes.flatMap((scope) => {
		const address = configIn(project, `${scope}:registry`, asking);
		return address === undefined ? [] : [[scope, originOf(`${scope}:registry`, address)] as const];
	});
	const address = configIn(project, "registry", asking) ?? "https://registry.npmjs.org/";
	return {
		default: originOf("registry", address),
		...(own.length > 0 ? { scopes: Object.fromEntries(own) } : {}),
	};
}

/** One package outside the release, read from the project pnpm installed it into, or why not. */
function outsideOf(
	project: string,
	lock: string,
	name: string,
	release: Release,
	registries: Registries,
): Outside | string[] {
	const recorded = outsideLock.recordOf(lock, name, registries);
	const dir = installedIn(project, name);
	const read = Object.fromEntries(files.map((file) => [file, readIn(dir, file)]));
	const unread = files.flatMap((file) => read[file]?.refusal ?? []);
	if (unread.length > 0) return unread;
	const text = read["package.json"]?.text;
	if (text === undefined) return ["has no package.json"];
	let manifest: Json;
	try {
		manifest = JSON.parse(text) as Json;
	} catch {
		return ["its package.json is not JSON"];
	}
	if (!isObject(manifest)) return ["its package.json is not an object"];
	if (manifest.name !== name) return [`its manifest names ${String(manifest.name)}`];
	if (manifest.version !== recorded.version) {
		return [
			`its manifest is ${String(manifest.version)}, where the lockfile records ${recorded.version}`,
		];
	}
	const scripts = rangesOf(manifest.scripts);
	const refusals = installScripts
		.filter((s) => scripts[s] !== undefined)
		.map((s) => `it runs ${s} when installed`);
	const { declaration, refusals: declared } = declarationOf(name, manifest.authProvider);
	refusals.push(...declared);
	if (!loadsSubpath(manifest.exports, "./module")) refusals.push("exports no ./module");
	if (declaration === undefined) return refusals;
	refusals.push(...copyRefusals(manifest, declaration, release));
	const record: OutsideRecord = {
		...recorded,
		dependencies: rangesOf(manifest.dependencies),
		optionalDependencies: rangesOf(manifest.optionalDependencies),
		peerDependencies: rangesOf(manifest.peerDependencies),
		peerDependenciesMeta: isObject(manifest.peerDependenciesMeta)
			? (manifest.peerDependenciesMeta as OutsideRecord["peerDependenciesMeta"])
			: {},
	};
	const prefix = `${name}: `;
	refusals.push(
		...outsideLock
			.refusals(lock, [record], {}, registries)
			.map((r) => (r.startsWith(prefix) ? r.slice(prefix.length) : r)),
	);
	if (refusals.length > 0) return refusals;
	const { "config.example": fragment, "README.md": card, "reference.conf": references } = read;
	return {
		declaration,
		record,
		...(fragment?.text !== undefined ? { fragment: fragment.text } : {}),
		...(card?.text !== undefined ? { card: card.text } : {}),
		...(references?.text !== undefined ? { references: references.text } : {}),
	};
}

/**
 * The packages outside the release named, as read from `project`, where the operator had pnpm
 * install them: each one's record from the project's lockfile, its manifest and files from its
 * `node_modules`, and the registries the project installs from (pnpm's settings there). Refuses,
 * naming each, what cannot be composed beside the release.
 */
export function readOutside(
	project: string,
	names: readonly string[],
	release: Release,
	asking: Asking = {},
): Read {
	const refusals: string[] = [];
	const said = (name: string, why: readonly string[]) =>
		refusals.push(...why.map((w) => `${name}: ${w}`));
	const named = names.filter((name) => {
		try {
			namesPackages([name]);
		} catch (error) {
			refusals.push((error as Error).message);
			return false;
		}
		if (releaseScopes.some((scope) => name.startsWith(scope)))
			said(name, ["a name in the release's scope"]);
		return !releaseScopes.some((scope) => name.startsWith(scope));
	});
	if (refusals.length > 0) throw new Error(refusals.join("; "));
	const registries = registriesIn(project, named, asking);
	if (named.length === 0) return { outside: [], registries };
	const lock = readFileSync(join(project, "pnpm-lock.yaml"), "utf8");
	const read: Outside[] = [];
	for (const name of named) {
		try {
			const outside = outsideOf(project, lock, name, release, registries);
			if (Array.isArray(outside)) said(name, outside);
			else read.push(outside);
		} catch (error) {
			refusals.push((error as Error).message);
		}
	}
	if (refusals.length > 0) throw new Error(refusals.join("; "));
	return { outside: read, registries };
}
