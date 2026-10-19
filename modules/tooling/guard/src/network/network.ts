import { join } from "node:path";
import ts from "typescript";
import { budgetsAsTest, type Scope } from "../units.ts";
import type { Pkg } from "../workspace.ts";

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

/** Each place a file reaches the network, as `module name`, `module` (imported whole), a client, or a global. */
export function reachesOf(path: string): string[] {
	// The file alone, bound by the compiler: a name resolves to the declaration in scope where it is used.
	const program = ts.createProgram([path], { noLib: true, noResolve: true, types: [] });
	const file = program.getSourceFile(path) as ts.SourceFile;
	const checker = program.getTypeChecker();
	const found: string[] = [];
	/** Whether the name used here is declared in this file, so not the global. */
	const local = (name: ts.Identifier) =>
		checker.getSymbolAtLocation(name)?.declarations?.some((d) => d.getSourceFile() === file) ===
		true;
	for (const statement of file.statements) {
		if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier))
			continue;
		const clause = statement.importClause;
		if (!clause || clause.isTypeOnly) continue;
		const specifier = statement.moduleSpecifier.text;
		const client = clientOf(specifier);
		if (client) {
			found.push(client);
			continue;
		}
		if (processes.includes(nodeName(specifier))) {
			found.push(nodeName(specifier));
			continue;
		}
		const names = reaching[nodeName(specifier)];
		if (!names) continue;
		const named = clause.namedBindings;
		if (clause.name || (named && ts.isNamespaceImport(named))) found.push(nodeName(specifier));
		if (named && ts.isNamedImports(named)) {
			for (const element of named.elements) {
				const name = (element.propertyName ?? element.name).text;
				if (!element.isTypeOnly && names.includes(name))
					found.push(`${nodeName(specifier)} ${name}`);
			}
		}
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

/** G26: product code reaches the network only as the words its manifest declares let it, each stated on its card. */
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
	const reached = new Set<string>();
	for (const file of s.sources(p)) {
		if (s.isTest(file) || budgetsAsTest(s, p, file)) continue;
		for (const reach of reachesOf(join(p.dir, file))) {
			reached.add(reach);
			if (!covers(allowed, reach)) s.report(rule, `${p.name}/${file}`, reach);
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
}
