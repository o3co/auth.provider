/** The attack surface reference: what reaches the provider from outside, and what it reaches out to. */

import { join } from "node:path";
import { full, optIns } from "@mod/combinations";
import type { Pkg } from "@mod/guard-imports";
import type { RouteSeen } from "../assembled.ts";
import { clientSectionsOf, idpTypesOf, sectionsIn } from "../configuration.ts";
import { routesIn } from "../routes.ts";
import { type Coverage, coverage } from "./coverage.ts";

/** A setting as the reference reads it: its key path, the package that owns it, and its default. */
export interface Setting {
	readonly key: string;
	readonly owner: string;
	readonly default?: unknown;
}

/** A package as the reference reads it, from its manifest. */
export interface PackageSeen {
	readonly name: string;
	readonly network?: string;
	/** Whether it has a module an app composes. */
	readonly composable: boolean;
	/** Whether it depends on `outbound`, so may reach another server. */
	readonly reachesOut: boolean;
}

/** What the reference is made from. */
export interface SurfaceInput {
	readonly routes: readonly RouteSeen[];
	readonly settings: readonly Setting[];
	readonly packages: readonly PackageSeen[];
	/** The packages the full template with every opt-in composes. */
	readonly composed: readonly string[];
	/** The packages that may reach private addresses, each declaring it in its `narrower`. */
	readonly privateReach: readonly string[];
	readonly coverage: Coverage;
}

const last = (key: string) => key.slice(key.lastIndexOf(".") + 1);

/** A key that holds a secret by its name: its last segment names one, or ends in one (`client-secret`). */
export const secretByName = (key: string) =>
	/^(secret|password|credential|private-key|key|hash)$|-(secret|password|credential)$/.test(
		last(key),
	);

/** A key that weakens a guarantee by its name, as the release policy asks such keys to be named. */
export const looseningByName = (key: string) =>
	/^(accept-.+|insecure-.+|fail-mode|on-unavailable|durability|replication|subject-check)$/.test(
		last(key),
	);

/** A key whose name makes it a candidate to weaken a guarantee, to be classified one way or the other. */
export const looseningCandidate = (key: string) =>
	/(allow|plain|keep-|exempt|disable|skip|loose|unsafe|any|trust|insecure|accept|volatile|proxy)/.test(
		last(key),
	);

/** A key whose name makes it a candidate to name a destination, to be classified one way or the other. */
export const destinationCandidate = (key: string) =>
	/(host|api|issuer|server|discovery)/.test(last(key));

/** A key that names where the provider reaches out to. */
export const destinationByName = (key: string) =>
	/(url|uri|endpoint|^hosts|-hosts)$/.test(last(key));

/** A route a `HEAD` reaches: `http` answers it for a `GET` that does not change state. */
export const answersHead = (r: RouteSeen) => r.method === "GET" && r.changesState !== true;

const cell = (text: string) => text.replaceAll("|", "\\|");
const code = (text: string) => `\`${text}\``;
const defaultOf = (value: unknown) => (value === undefined ? "" : code(JSON.stringify(value)));

/** The reference, generated. */
export function attackSurfaceOf(input: SurfaceInput): string {
	const { routes, settings, packages, composed, privateReach } = input;
	const c = input.coverage;
	const owned = new Map(settings.map((s) => [s.key, s]));
	const ownerOf = (key: string) => owned.get(key)?.owner ?? "";
	const methods = [...new Set(routes.map((r) => r.method))].sort();
	const counted = methods
		.map((m) => `${m} ${routes.filter((r) => r.method === m).length}`)
		.join(", ");
	const stateGets = routes.filter((r) => r.method === "GET" && r.changesState === true);
	const otherSites = routes.filter((r) => r.ownSite !== undefined && "reason" in r.ownSite);
	const uncounted = routes.filter((r) => r.perSource !== undefined && "reason" in r.perSource);
	const reasonOf = (kept: RouteSeen["ownSite"]) =>
		kept && "reason" in kept ? cell(kept.reason) : "";
	const product = packages.filter((p) => p.composable);
	const left = product.filter((p) => !composed.includes(p.name)).map((p) => code(p.name));
	const network = packages.filter((p) => p.network !== undefined);
	const reaching = packages.filter((p) => p.reachesOut);
	const secrets = [
		...settings.filter((s) => secretByName(s.key) && !c.notSecrets.some((n) => n.key === s.key)),
	].map((s) => ({ key: s.key, owner: s.owner, holds: "by its name" }));
	const named = c.secrets.map((s) => ({ key: s.key, owner: ownerOf(s.key), holds: s.holds }));
	const loosening = [
		...settings
			.filter((s) => looseningByName(s.key) && !c.loosening.some((l) => l.key === s.key))
			.map((s) => ({ ...s, weakens: "named so (`accept-*` and the like)" })),
		...c.loosening.map((l) => ({
			...owned.get(l.key),
			key: l.key,
			owner: ownerOf(l.key),
			weakens: l.weakens,
		})),
	].sort((a, b) => (a.key < b.key ? -1 : 1));
	const destinations = [
		...settings
			.filter((s) => destinationByName(s.key))
			.map((s) => ({ ...s, reaches: "by its name" })),
		...c.destinations.map((d) => ({
			...owned.get(d.key),
			key: d.key,
			owner: ownerOf(d.key),
			reaches: d.reaches,
		})),
	].sort((a, b) => (a.key < b.key ? -1 : 1));
	const crossOrigin = routes.filter((r) => r.cors);
	return `${[
		"# Attack surface",
		"",
		"Generated by `references` from the full template with every opt-in, on its defaults and the trial's settings, and from the hand-written coverage in `modules/tooling/references/src/attack-surface/coverage.ts`: do not edit; run `pnpm --filter @mod/references run configuration`.",
		"It is one composition, not every one: a module another composition adds opens what its card says. A list here is read from what modules declare, and a declaration is its owner's claim, not a proof.",
		"",
		"## What this composition leaves out",
		"",
		`Packages with a module the full template with every opt-in does not compose: ${left.join(", ") || "none"}.`,
		"",
		"## Routes",
		"",
		`${routes.length} routes (${counted}); each is in [the route reference](routes.md).`,
		"",
		`- \`HEAD\` is answered for each \`GET\` that does not change state (${routes.filter(answersHead).length} of them), and for no other: a \`GET\` that changes state is never reached by \`HEAD\`.`,
		"- A CORS preflight (`OPTIONS` with `Access-Control-Request-Method`) is answered for the routes a path reaches that take cross-origin requests.",
		"",
		"`GET` routes that change state:",
		"",
		...(stateGets.length
			? stateGets.map((r) => `- ${code(r.path)} (${code(r.owner)})`)
			: ["- none"]),
		"",
		"Routes that take other sites' requests, by their reason:",
		"",
		"| Method | Path | From | Reason |",
		"|---|---|---|---|",
		...otherSites.map(
			(r) => `| ${r.method} | ${code(r.path)} | ${code(r.owner)} | ${reasonOf(r.ownSite)} |`,
		),
		"",
		"Routes that count no source, by their reason:",
		"",
		"| Method | Path | From | Reason |",
		"|---|---|---|---|",
		...uncounted.map(
			(r) => `| ${r.method} | ${code(r.path)} | ${code(r.owner)} | ${reasonOf(r.perSource)} |`,
		),
		"",
		"Routes that take cross-origin requests (CORS):",
		"",
		...(crossOrigin.length
			? crossOrigin.map((r) => `- ${r.method} ${code(r.path)} (${code(r.owner)})`)
			: ["- none"]),
		"",
		"Routes that send the browser elsewhere, which `outbound` never sees:",
		"",
		"| Method | Path | To |",
		"|---|---|---|",
		...c.redirects.map((r) => `| ${r.method} | ${code(r.path)} | ${r.to} |`),
		"",
		"## Reaching out",
		"",
		"A package that depends on `outbound` can reach another server through it; this says who can, not every call or where its destination comes from.",
		"",
		`- Packages that speak to the network themselves (\`network\` in their manifest): ${network.map((p) => `${code(p.name)} (${p.network})`).join(", ")}.`,
		`- Packages that depend on \`outbound\`: ${reaching.map((p) => code(p.name)).join(", ")}.`,
		`- Packages that may reach private addresses at URLs of the operator's configuration (\`narrower\` in their manifest): ${privateReach.map(code).join(", ")}.`,
		"",
		"Settings that name where it reaches:",
		"",
		"| Setting | From | Default | Reaches |",
		"|---|---|---|---|",
		...destinations.map(
			(s) =>
				`| ${code(s.key)} | ${s.owner ? code(s.owner) : ""} | ${defaultOf(s.default)} | ${s.reaches} |`,
		),
		"",
		"## Secrets in settings",
		"",
		"| Setting | From | Holds |",
		"|---|---|---|",
		...[...secrets, ...named]
			.sort((a, b) => (a.key < b.key ? -1 : 1))
			.map((s) => `| ${code(s.key)} | ${s.owner ? code(s.owner) : ""} | ${s.holds} |`),
		"",
		"Secrets kept in stores (sealed transactions, secret hashes) are in each module's card, under Data.",
		"",
		"## Settings that weaken a guarantee",
		"",
		"| Setting | From | Default | Weakens |",
		"|---|---|---|---|",
		...loosening.map(
			(l) =>
				`| ${code(l.key)} | ${l.owner ? code(l.owner) : ""} | ${defaultOf(l.default)} | ${l.weakens} |`,
		),
		"",
		"## What the operator does by hand",
		"",
		...c.manualTasks.map((t) => `- [${t.what}](runbook.md#${t.anchor})`),
	].join("\n")}\n`;
}

/**
 * The packages that may reach private addresses at URLs of the operator's configuration: those
 * declaring, in `narrower`, the property its owner's `narrower` holds to declaration.
 */
export function privateReachOf(packages: readonly Pkg[]): readonly string[] {
	const stated = packages
		.map(({ manifest }) => manifest.narrower)
		.find(
			(value): value is { property: string } =>
				typeof value === "object" &&
				value !== null &&
				typeof (value as { property?: unknown }).property === "string",
		);
	return packages
		.filter(({ manifest }) => stated !== undefined && manifest.narrower === stated.property)
		.map(({ name }) => name)
		.sort();
}

/** Everything the reference is made from, read from the workspace at `root` and its packages. */
export async function attackSurfaceIn(
	root: string,
	packages: readonly Pkg[],
): Promise<SurfaceInput> {
	const sections = [
		...(await sectionsIn(packages)),
		...(await clientSectionsOf(root, packages)),
		...(await idpTypesOf(root, packages)),
	];
	// A key held in several variants is one setting of its owner, its first default shown.
	const settings = [
		...new Map(
			sections
				.flatMap((s) => [...s.rows, ...(s.items ?? [])].map((r) => ({ r, owner: s.owner })))
				.toReversed()
				.map(({ r, owner }) => [
					`${owner} ${r.key}`,
					{ key: r.key, owner, ...(r.default === undefined ? {} : { default: r.default }) },
				]),
		).values(),
	].toReversed();
	const listed = packages.map(({ name, manifest }) => {
		return {
			name,
			...(manifest.network ? { network: manifest.network as string } : {}),
			composable: manifest.exports?.["./module"] !== undefined && manifest.kind !== "verification",
			reachesOut: Object.hasOwn(manifest.dependencies ?? {}, "@mod/outbound"),
		};
	});
	const sorted = listed.sort((a, b) => (a.name < b.name ? -1 : 1));
	return {
		routes: await routesIn(root, packages),
		settings: settings.sort((a, b) => (a.key < b.key ? -1 : 1)),
		packages: sorted,
		composed: full(optIns()),
		privateReach: privateReachOf(packages),
		coverage,
	};
}

/** Where the reference lies in the workspace. */
export const attackSurfaceFile = (root: string) => join(root, "docs", "attack-surface.md");
