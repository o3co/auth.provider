import { join } from "node:path";
import type { Pkg } from "@mod/guard-imports";
import ts from "typescript";
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

/** Whether an identifier is read as a value: not a property's name, a declaration's name, or in a type. */
function referenced(node: ts.Identifier): boolean {
	const parent = node.parent;
	if (ts.isPropertyAccessExpression(parent) && parent.name === node) return false;
	if (
		(ts.isPropertyAssignment(parent) ||
			ts.isPropertyDeclaration(parent) ||
			ts.isPropertySignature(parent) ||
			ts.isMethodDeclaration(parent) ||
			ts.isMethodSignature(parent) ||
			ts.isImportSpecifier(parent) ||
			ts.isExportSpecifier(parent)) &&
		parent.name === node
	) {
		return false;
	}
	for (let at: ts.Node = parent; !ts.isSourceFile(at); at = at.parent) {
		if (ts.isTypeNode(at)) return false;
	}
	return true;
}

/** What an import or a re-export binds of a module: all of it, or values and types by name. */
interface Bound {
	readonly specifier: string;
	/** A default, a namespace, or `export *`: the module whole. */
	readonly whole: boolean;
	readonly named: readonly { readonly name: string; readonly typeOnly: boolean }[];
}

/** The binding of an import or a re-export, read alike as the card says; none for a type-only one or another statement. */
function boundOf(statement: ts.Statement): Bound | undefined {
	if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier)) {
		const clause = statement.importClause;
		if (!clause || clause.isTypeOnly) return undefined;
		const bindings = clause.namedBindings;
		return {
			specifier: statement.moduleSpecifier.text,
			whole:
				clause.name !== undefined || (bindings !== undefined && ts.isNamespaceImport(bindings)),
			named:
				bindings && ts.isNamedImports(bindings)
					? bindings.elements.map((e) => ({
							name: (e.propertyName ?? e.name).text,
							typeOnly: e.isTypeOnly,
						}))
					: [],
		};
	}
	if (
		ts.isExportDeclaration(statement) &&
		!statement.isTypeOnly &&
		statement.moduleSpecifier !== undefined &&
		ts.isStringLiteral(statement.moduleSpecifier)
	) {
		const clause = statement.exportClause;
		const elements =
			clause && ts.isNamedExports(clause)
				? clause.elements.map((e) => ({
						name: (e.propertyName ?? e.name).text,
						typeOnly: e.isTypeOnly,
					}))
				: [];
		return {
			specifier: statement.moduleSpecifier.text,
			whole:
				clause === undefined ||
				ts.isNamespaceExport(clause) ||
				elements.some((e) => e.name === "default" && !e.typeOnly),
			named: elements.filter((e) => e.name !== "default"),
		};
	}
	return undefined;
}

/** What a binding reaches: a client or a process, a module whole, or each value named; nothing where it binds types alone. */
function reachedBy(bound: Bound): string[] {
	const values = bound.named.filter((n) => !n.typeOnly).map((n) => n.name);
	if (!bound.whole && values.length === 0) return [];
	const client = clientOf(bound.specifier);
	if (client) return [client];
	const module = nodeName(bound.specifier);
	if (processes.includes(module)) return [module];
	const names = reaching[module];
	if (!names) return [];
	return [
		...(bound.whole ? [module] : []),
		...values.filter((v) => names.includes(v)).map((v) => `${module} ${v}`),
	];
}

/** Each place a file reaches the network, as `module name`, `module` (imported whole), a client, or a global. */
export function reachesOf(path: string): string[] {
	// The file alone, bound by the compiler: a name resolves to the declaration in scope where it is used.
	// JavaScript sources too: a `.mjs` file is read as a `.ts` one is.
	const program = ts.createProgram([path], {
		noLib: true,
		noResolve: true,
		types: [],
		allowJs: true,
	});
	const file = program.getSourceFile(path) as ts.SourceFile;
	const checker = program.getTypeChecker();
	const found: string[] = [];
	/** Whether the name used here is declared in this file, so not the global. */
	const local = (name: ts.Identifier) =>
		checker.getSymbolAtLocation(name)?.declarations?.some((d) => d.getSourceFile() === file) ===
		true;
	for (const statement of file.statements) {
		const bound = boundOf(statement);
		if (bound !== undefined) found.push(...reachedBy(bound));
	}
	/** A module loaded by `import()` or `require` reaches as one imported whole; one named at run time, unknown. */
	const loaded = (specifier: ts.Expression | undefined) => {
		if (!specifier || !ts.isStringLiteralLike(specifier)) return "import()";
		const client = clientOf(specifier.text);
		const module = nodeName(specifier.text);
		return client ?? (reaching[module] || processes.includes(module) ? module : undefined);
	};
	/** A network global named as a property of the global object, by a dot or a string literal. */
	const globalReached = (node: ts.Node) => {
		const owner =
			ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)
				? node.expression
				: undefined;
		if (!owner || !ts.isIdentifier(owner) || !globalObjects.includes(owner.text) || local(owner))
			return undefined;
		const name = ts.isPropertyAccessExpression(node)
			? node.name.text
			: ts.isElementAccessExpression(node) && ts.isStringLiteralLike(node.argumentExpression)
				? node.argumentExpression.text
				: undefined;
		return name && globals.includes(name) ? name : undefined;
	};
	const uses = (node: ts.Node): void => {
		if (ts.isCallExpression(node)) {
			const callee = node.expression;
			const requiring = ts.isIdentifier(callee) && callee.text === "require" && !local(callee);
			if (callee.kind === ts.SyntaxKind.ImportKeyword || requiring) {
				const reach = loaded(node.arguments[0]);
				if (reach) found.push(reach);
			}
		}
		const reached = globalReached(node);
		if (reached) found.push(reached);
		if (ts.isIdentifier(node) && globals.includes(node.text) && !local(node) && referenced(node)) {
			found.push(node.text);
		}
		ts.forEachChild(node, uses);
	};
	uses(file);
	return found;
}

/** Whether a declared word lets a package reach this; a module imported whole needs a word that names it. */
const covers = (allowed: readonly string[], reach: string) =>
	allowed.includes(reach) || allowed.some((a) => a.split(" ")[0] === reach);

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
		return launchRefusal(p.dir, file, helper);
	};
	const reached = new Set<string>();
	/** The starters already held to the form, by what they reach. */
	const checked = new Set<string>();
	for (const file of s.sources(p)) {
		if (s.isTest(file) || budgetsAsTest(s, p, file)) continue;
		const reaches = reachesOf(join(p.dir, file));
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
		const reaches = reachesOf(path);
		for (const reach of reaches) reached.add(reach);
		if (!importsLookupAlone(path, reaches)) {
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
