import { join } from "node:path";
import {
	type Edge,
	type EdgeBinding,
	type FileFacts,
	lexicalAnalysis,
	type Pkg,
} from "@mod/guard-imports";
import type ts from "typescript";
import { budgetsAsTest, type Scope } from "../units.ts";
import { forksOf, importsLookupAlone, isPlainHelper, launchRefusal } from "./forks.ts";

/** Names that ask a resolver, and so reach the network. */
const resolving = [
	"lookup",
	"lookupService",
	"resolve",
	"resolve4",
	"resolve6",
	"resolveAny",
	"resolveCaa",
	"resolveCname",
	"resolveMx",
	"resolveNaptr",
	"resolveNs",
	"resolvePtr",
	"resolveSoa",
	"resolveSrv",
	"resolveTxt",
	"reverse",
	"Resolver",
];
/** Each Node module's names that open a connection or a server; any other name is not counted. */
const reaching: Readonly<Record<string, readonly string[]>> = {
	"node:http": ["request", "get", "Agent", "ClientRequest", "createServer", "Server"],
	"node:https": ["request", "get", "Agent", "createServer", "Server"],
	"node:net": ["connect", "createConnection", "createServer", "Server", "Socket"],
	"node:tls": ["connect", "createServer", "Server", "TLSSocket"],
	"node:dgram": ["createSocket", "Socket"],
	"node:http2": ["connect", "createServer", "createSecureServer"],
	"node:dns": [...resolving, "promises"],
	"node:dns/promises": resolving,
};
/** Modules any value import of which reaches out: a process started can reach anything. */
const processes = ["node:child_process"];
/** Libraries that are network clients, by package name. */
const clients = ["ioredis", "nodemailer", "undici", "ws", "node-fetch", "axios", "got"];
/** Globals that reach the network when no local binding of the name hides them. */
const globals = ["fetch", "WebSocket", "EventSource"];
/** Names of the global object, through which a global can be reached as a property. */
const globalObjects = ["globalThis", "global", "self", "window"];

/** What each word lets a package reach: `module name` pairs, a module whole, or a client library. */
const words: Readonly<Record<string, readonly string[]>> = {
	"serves-http": ["node:http createServer", "node:http Server"],
	outbound: [
		"node:http request",
		"node:http Agent",
		"node:https request",
		"node:https Agent",
		"node:net connect",
		"node:tls connect",
		"node:dns lookup",
		"node:dns/promises lookup",
	],
	redis: ["ioredis"],
	smtp: ["node:net connect", "node:tls connect", "nodemailer"],
};
/** Words whose reach is a server the deployment provides, which the package's card then states under Deployment. */
const provided = ["redis", "smtp"];

const nodeName = (specifier: string) =>
	specifier.startsWith("node:") ? specifier : `node:${specifier}`;
const clientOf = (specifier: string) =>
	clients.find((c) => specifier === c || specifier.startsWith(`${c}/`));

/** What an import or a re-export reaches: a client or a process, a module whole (a default, by name or not, a namespace, `export *`), or each value named; nothing where it binds types alone. */
function reachedByBindings(edge: Edge): string[] {
	const specifier = edge.specifier.text ?? "";
	const values = edge.bindings.filter((b) => !b.typeOnly);
	const isDefault = (b: EdgeBinding) => b.form === "named" && b.imported === "default";
	const whole = values.some((b) => b.form !== "named" || isDefault(b));
	const named = values.filter((b) => b.form === "named" && !isDefault(b)).map((b) => b.imported);
	if (!whole && named.length === 0) return [];
	const client = clientOf(specifier);
	if (client) return [client];
	const module = nodeName(specifier);
	if (processes.includes(module)) return [module];
	const names = reaching[module];
	if (!names) return [];
	return [
		...(whole ? [module] : []),
		...named.filter((v) => names.includes(v)).map((v) => `${module} ${v}`),
	];
}

/** What a module loaded whole reaches (`import()`, a loader's call, `import = require`); one named at run time, unknown. */
function reachedByLoad(edge: Edge): string | undefined {
	const specifier = edge.specifier.text;
	if (specifier === undefined) return "import()";
	const module = nodeName(specifier);
	return (
		clientOf(specifier) ?? (reaching[module] || processes.includes(module) ? module : undefined)
	);
}

/** Each place a file's facts reach the network (its imports and re-exports, then the rest as written), as `module name`, `module` (imported whole), a client, or a global. */
export function reachesIn(facts: FileFacts): string[] {
	const bound = facts.edges
		.filter((e) => (e.form === "import" || e.form === "export-from") && e.loads)
		.flatMap(reachedByBindings);
	const at = (node: ts.Node, rank: number) => ({ start: node.getStart(), rank });
	const placed: { start: number; rank: number; reach: string }[] = [];
	for (const edge of facts.edges) {
		if (edge.form !== "dynamic-import" && edge.form !== "require" && edge.form !== "import-equals")
			continue;
		if (!edge.loads) continue;
		const reach = reachedByLoad(edge);
		if (reach) placed.push({ ...at(edge.node, 0), reach });
	}
	for (const member of facts.members) {
		const owner = member.object;
		const global =
			owner.role === "value" &&
			owner.binding?.kind === "unbound" &&
			globalObjects.includes(owner.node.text);
		if (global && member.name && globals.includes(member.name)) {
			placed.push({ ...at(member.node, 1), reach: member.name });
		}
	}
	for (const reference of facts.references) {
		if (reference.role !== "value" || reference.binding?.kind !== "unbound") continue;
		if (globals.includes(reference.node.text)) {
			placed.push({ ...at(reference.node, 2), reach: reference.node.text });
		}
	}
	placed.sort((a, b) => a.start - b.start || a.rank - b.rank);
	return [...bound, ...placed.map((p) => p.reach)];
}

/** Each place a file reaches the network, read on its own. */
export const reachesOf = (path: string): string[] =>
	reachesIn(lexicalAnalysis([path]).factsOf(path));

/** The plain helpers each package's `forks` names, by path: files a run reads beside the sources. */
export const helpersOf = (packages: readonly Pkg[]) =>
	packages.flatMap((p) =>
		[...(forksOf(p.manifest.forks)?.values() ?? [])]
			.map((helper) => join(p.dir, helper))
			.filter(isPlainHelper),
	);

/** Whether the declared words let a package reach this; a module imported whole reaches each of its names, so they must name every one. */
const covers = (allowed: readonly string[], reach: string) =>
	allowed.includes(reach) ||
	(reaching[reach]?.every((name) => allowed.includes(`${reach} ${name}`)) ?? false);

/** G26: product code reaches the network only as the words its manifest declares let it, each stated on its card. G27: a word reaching a server the deployment provides asks a Deployment section. */
export function networkRules(s: Scope, p: Pkg) {
	if (!s.budget.productKinds.includes(s.kindOf(p))) return;
	const rule = "G26 the network is reached through outbound, or as a package declares";
	const declared = [p.manifest.network ?? []].flat().map(String);
	const known = declared.filter((word) => {
		const ok = Object.hasOwn(words, word);
		if (!ok) s.report(rule, p.name, `network ${word} is no word guard knows`);
		return ok;
	});
	const allowed = known.flatMap((word) => words[word] ?? []);
	const forks = forksOf(p.manifest.forks);
	if (forks === undefined) s.report(rule, p.name, "forks maps a shipped file to its helper's file");
	const oneStarter = (forks?.size ?? 0) <= 1;
	if (!oneStarter) s.report(rule, p.name, "forks names one starter and its helper");
	/** Why a file starting a process is not the one starter starting its helper; none where it is. */
	const forkRefusal = (file: string) => {
		const helper = forks?.get(file);
		if (helper === undefined) return "forks does not name it";
		if (!known.includes("outbound")) return "forks needs the word outbound";
		if (!oneStarter) return "forks names one starter and its helper";
		return launchRefusal(s.factsOf(p, file), p.dir, file, helper);
	};
	const reached = new Set<string>();
	/** The starters already held to the form, by what they reach. */
	const checked = new Set<string>();
	for (const file of s.sources(p)) {
		if (s.isTest(file) || budgetsAsTest(s, p, file)) continue;
		const reaches = reachesIn(s.factsOf(p, file));
		for (const reach of reaches) {
			reached.add(reach);
			if (reach === "node:child_process") {
				checked.add(file);
				const why = forkRefusal(file);
				if (why !== undefined) s.report(rule, `${p.name}/${file}`, `${reach} (${why})`);
				continue;
			}
			if (!covers(allowed, reach)) s.report(rule, `${p.name}/${file}`, reach);
		}
	}
	// Every starter `forks` names is a shipped source this rule reads.
	const shipped = new Set(
		s.sources(p).filter((file) => !s.isTest(file) && !budgetsAsTest(s, p, file)),
	);
	for (const starter of forks?.keys() ?? []) {
		if (!shipped.has(starter)) {
			s.report(rule, `${p.name}/${starter}`, "(forks names it, but it is no shipped source)");
			continue;
		}
		// Held to the form whatever it reaches: one starting nothing as written is refused all the same.
		if (checked.has(starter)) continue;
		const why = forkRefusal(starter);
		if (why !== undefined) s.report(rule, `${p.name}/${starter}`, `node:child_process (${why})`);
	}
	// Every helper forks names, whether or not it is read as a source: it resolves names and nothing else.
	for (const helper of new Set(forks?.values() ?? [])) {
		const path = join(p.dir, helper);
		// Never parsed unless it is one: a card, a directory or a link is no source to read.
		if (!isPlainHelper(path)) {
			s.report(rule, `${p.name}/${helper}`, "(forks names it, but it is no plain .mjs file)");
			continue;
		}
		const facts = s.factsOf(p, helper);
		const reaches = reachesIn(facts);
		for (const reach of reaches) reached.add(reach);
		if (!importsLookupAlone(facts, reaches)) {
			s.report(rule, `${p.name}/${helper}`, "(imports node:dns/promises' lookup alone)");
		}
	}
	for (const word of known) {
		if (!(p.card ?? "").includes(`\`network\`: \`${word}\``)) {
			s.report(rule, p.name, `card states \`network\`: \`${word}\``);
		}
		if (![...reached].some((reach) => covers(words[word] ?? [], reach))) {
			s.report(rule, p.name, `${word} reaches nothing here`);
		}
	}
	// G27: what the server must be is the operator's to read on the card, in one place.
	if (known.some((word) => provided.includes(word)) && !/^## Deployment$/m.test(p.card ?? "")) {
		s.report(
			"G27 a package that talks to a server the deployment provides states that server under Deployment",
			p.name,
			"card has no `## Deployment` section",
		);
	}
}
