import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { assemble } from "@mod/kernel";
import { parse } from "@o3co/ts.hocon";
import { expect, it, vi } from "vitest";
import { fragmentFile, fragmentsIn, settingsOf } from "../src/fragments.ts";
import { isTree, packageDirs, root, type Tree } from "./full-app.ts";

// These tests read the whole workspace, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

const packages = [...packageDirs]
	.map(([name, path]) => ({ name, path }))
	.filter((p) => p.path !== root);

/** Each scalar of a value, with its path: objects and lists are walked into. */
function scalars(value: unknown, path: string): [string, unknown][] {
	if (Array.isArray(value)) return value.flatMap((item, i) => scalars(item, `${path}.${i}`));
	if (isTree(value)) return Object.entries(value).flatMap(([k, v]) => scalars(v, `${path}.${k}`));
	return [[path, value]];
}

/** How a sample the schema must not take begins: a secret's, or another string's. */
const replace = "REPLACE-";
const isReplace = (value: unknown) => typeof value === "string" && value.startsWith(replace);

/**
 * Why a fragment's value is not a placeholder, or undefined: hosts, URLs and mail under `.invalid`,
 * secrets and other strings `REPLACE-…`, a one-word choice, a number or a boolean.
 */
function notPlaceholder(value: unknown, path = ""): string | undefined {
	// A listen address is no host reached from outside: the loopback, or every address in a container.
	if (path === "http.host") {
		return value === "127.0.0.1" || value === "0.0.0.0"
			? undefined
			: "a listen address of neither kind";
	}
	if (typeof value === "number" || typeof value === "boolean") return undefined;
	if (typeof value !== "string") return "neither a string, a number nor a boolean";
	const invalid = (host: string) => host === "invalid" || host.endsWith(".invalid");
	if (value.includes("://")) {
		return URL.canParse(value) && invalid(new URL(value).hostname)
			? undefined
			: "a URL not under .invalid";
	}
	if (value.includes("@")) {
		const domain = value.slice(value.lastIndexOf("@") + 1).replace(/>$/, "");
		return invalid(domain) ? undefined : "a mail address not under .invalid";
	}
	if (isReplace(value)) return undefined;
	if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(value)) {
		return invalid(value) ? undefined : "a host not under .invalid";
	}
	// Even all zero bytes: a sample in the repo that the schema takes would boot as a known secret.
	if (/^[A-Za-z0-9+/]{16,}={0,2}$/.test(value)) return "a secret not REPLACE-…";
	return /^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(value) ? undefined : "a string not REPLACE-…";
}

it("tells a placeholder from a value that could be real", () => {
	for (const ok of [
		"https://login.example.invalid/consent",
		"rediss://redis.example.invalid:6379",
		"auth@example.invalid",
		"Auth <auth@example.invalid>",
		"destination.example.invalid",
		"REPLACE-PKCS8-PEM-PRIVATE-KEY",
		"EdDSA",
		"self-signed",
		1000,
		true,
	]) {
		expect(notPlaceholder(ok), String(ok)).toBeUndefined();
	}
	for (const real of [
		"https://login.example.com",
		"auth@example.com",
		"smtp.example.com",
		"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"0123456789abcdef0123456789abcdef",
		"00000000000000000000000000000000",
		"-----BEGIN PRIVATE KEY-----",
		"a display name",
		null,
	]) {
		expect(notPlaceholder(real), String(real)).toBeDefined();
	}
	expect(notPlaceholder("127.0.0.1", "http.host")).toBeUndefined();
	expect(notPlaceholder("0.0.0.0", "http.host")).toBeUndefined();
	expect(notPlaceholder("10.0.0.1", "http.host")).toBeDefined();
	expect(notPlaceholder("127.0.0.1", "redis.url")).toBeDefined();
});

/** The builder a module's `./testing` names for its section's test configuration: `seal` → `sealConfig`. */
const builderName = (section: string) =>
	`${section.replace(/-([a-z0-9])/g, (_, c: string) => c.toUpperCase())}Config`;

/** The value at a path of dotted keys and list indexes, or undefined. */
const at = (value: unknown, path: string) =>
	path
		.split(".")
		.reduce<unknown>(
			(v, key) => (isTree(v) || Array.isArray(v) ? (v as Tree)[key] : undefined),
			value,
		);

/**
 * The section with each `REPLACE-` sample put by the value at its path in the module's test builder,
 * called with no arguments; or why it cannot be filled.
 */
function filled(
	section: string,
	tree: unknown,
	testing: Record<string, unknown> | undefined,
): { readonly section: unknown } | { readonly problems: string[] } {
	const samples = scalars(tree, section).filter(([, value]) => isReplace(value));
	if (samples.length === 0) return { section: tree };
	const name = builderName(section);
	const builder = testing?.[name];
	if (testing === undefined)
		return { problems: ["REPLACE- samples, but no ./testing to fill them"] };
	if (typeof builder !== "function") {
		return { problems: [`REPLACE- samples, but ./testing has no ${name}`] };
	}
	const built: unknown = builder();
	const missing = samples.filter(([path]) => at(built, path) === undefined);
	if (missing.length > 0) {
		return { problems: missing.map(([path]) => `${name}() holds nothing at ${path}`) };
	}
	const put = (value: unknown, path: string): unknown => {
		if (Array.isArray(value)) return value.map((item, i) => put(item, `${path}.${i}`));
		if (isTree(value)) {
			return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, put(v, `${path}.${k}`)]));
		}
		return isReplace(value) ? at(built, path) : value;
	};
	return { section: put(tree, section) };
}

it("fills a fragment's REPLACE- samples from its module's test builder, and says why when it cannot", () => {
	const tree = { keys: [{ id: "one", key: "REPLACE-KEY" }], name: "REPLACE-NAME", size: 1 };
	const sampleConfig = () => ({
		"my-section": { keys: [{ id: "test", key: "k" }], name: "n", size: 2, other: true },
	});
	expect(filled("my-section", tree, { mySectionConfig: sampleConfig })).toEqual({
		section: { keys: [{ id: "one", key: "k" }], name: "n", size: 1 },
	});
	expect(filled("my-section", { size: 1 }, undefined)).toEqual({ section: { size: 1 } });
	expect(filled("my-section", tree, undefined)).toEqual({
		problems: ["REPLACE- samples, but no ./testing to fill them"],
	});
	expect(filled("my-section", tree, { otherConfig: sampleConfig })).toEqual({
		problems: ["REPLACE- samples, but ./testing has no mySectionConfig"],
	});
	const lacking = () => ({ "my-section": { keys: [] } });
	expect(filled("my-section", tree, { mySectionConfig: lacking })).toEqual({
		problems: [
			"mySectionConfig() holds nothing at my-section.keys.0.key",
			"mySectionConfig() holds nothing at my-section.name",
		],
	});
});

interface Collected {
	readonly name: string;
	readonly tree: Tree;
	/** The section's name, and its StandardSchema as the kernel reads it; none for the kernel. */
	readonly section?: string;
	readonly schema?: { "~standard": { validate(value: unknown): unknown } } | undefined;
	/** The package's `./testing`, when it has one. */
	readonly testing?: Record<string, unknown>;
}

/** Every fragment of the workspace, with its module's section schema and test builders. */
async function collected(): Promise<Collected[]> {
	const withFragments = packages.filter((p) => existsSync(join(p.path, fragmentFile)));
	expect(withFragments.length).toBeGreaterThan(0);
	return Promise.all(
		withFragments.map(async (p) => {
			const tree = parse(readFileSync(join(p.path, fragmentFile), "utf8")).toObject() as Tree;
			const manifest = JSON.parse(readFileSync(join(p.path, "package.json"), "utf8"));
			const entry: string | undefined = manifest.exports?.["./module"];
			const testing: string | undefined = manifest.exports?.["./testing"];
			const module =
				entry === undefined
					? undefined
					: ((await import(join(p.path, entry))).default as {
							name: string;
							section?: Collected["schema"];
						});
			return {
				name: p.name,
				tree,
				...(module ? { section: module.name, schema: module.section } : {}),
				...(testing ? { testing: await import(join(p.path, testing)) } : {}),
			};
		}),
	);
}

const issuesOf = async (schema: Collected["schema"], value: unknown) => {
	const result = (await schema?.["~standard"].validate(value)) as { issues?: unknown } | undefined;
	return result && "issues" in result ? result.issues : undefined;
};

it("holds, in every fragment of the workspace, its module's section alone, with placeholders only", async () => {
	for (const f of await collected()) {
		const keys = Object.keys(f.tree);
		const [section] = keys;
		if (f.section === undefined) {
			// A package without a module is the kernel, which reads its own section: it boots on the
			// fragment alone, refusing any other section.
			await expect(assemble({ modules: [], config: f.tree }), f.name).resolves.toBeDefined();
		} else {
			expect(keys, f.name).toEqual([f.section]);
		}
		for (const [path, value] of scalars(f.tree[section ?? ""], section ?? "")) {
			expect(notPlaceholder(value, path), `${f.name}: ${path}`).toBeUndefined();
		}
	}
});

it("takes every fragment by its section's schema once its REPLACE- samples are filled from its module's test builder", async () => {
	for (const f of await collected()) {
		if (f.section === undefined) continue;
		const fill = filled(f.section, f.tree[f.section], f.testing);
		expect("problems" in fill ? fill.problems : [], f.name).toEqual([]);
		if ("section" in fill) expect(await issuesOf(f.schema, fill.section), f.name).toBeUndefined();
	}
});

it("refuses by its section's schema every fragment holding a REPLACE- sample, as it is", async () => {
	const withSamples = (await collected()).filter(
		(f) => f.section !== undefined && scalars(f.tree, "").some(([, value]) => isReplace(value)),
	);
	expect(withSamples.length).toBeGreaterThan(0);
	for (const f of withSamples) {
		expect(await issuesOf(f.schema, f.tree[f.section ?? ""]), f.name).toBeDefined();
	}
});

it("names each key's environment variable from the section and the key path, and refuses two keys reading one", async () => {
	const fixtures = join(import.meta.dirname, "fixtures", "collide");
	const [one, other] = await fragmentsIn([join(fixtures, "one"), join(fixtures, "other")]);
	if (!one || !other) throw new Error("fixtures missing");
	expect(settingsOf([one]).map((s) => [s.key, s.env])).toEqual([
		["audit-http.url", "AUDIT_HTTP_URL"],
		["audit-http.retry.max-ms", "AUDIT_HTTP_RETRY_MAX_MS"],
	]);
	expect(() => settingsOf([one, other])).toThrow(
		"audit-http.url and audit.http-url both read AUDIT_HTTP_URL",
	);
});

it("skips a package without a fragment, and refuses one holding other than one section", async () => {
	const fixtures = join(import.meta.dirname, "fixtures", "collide");
	expect(await fragmentsIn([join(fixtures, "none")])).toEqual([]);
	await expect(fragmentsIn([join(fixtures, "two")])).rejects.toThrow(
		"does not hold exactly one section",
	);
	await expect(fragmentsIn([join(fixtures, "one"), join(fixtures, "one")])).rejects.toThrow(
		"a second fragment for audit-http",
	);
});
