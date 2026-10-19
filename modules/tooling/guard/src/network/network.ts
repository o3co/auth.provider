import { readFileSync } from "node:fs";
import { join } from "node:path";
import ts from "typescript";
import { budgetsAsTest, type Scope } from "../units.ts";
import type { Pkg } from "../workspace.ts";

/** Each Node module's names that open a connection or a server; any other name is not counted. */
const reaching: Readonly<Record<string, readonly string[]>> = {
	"node:http": ["request", "get", "Agent", "ClientRequest", "createServer", "Server"],
	"node:https": ["request", "get", "Agent", "createServer", "Server"],
	"node:net": ["connect", "createConnection", "createServer", "Server", "Socket"],
	"node:tls": ["connect", "createServer", "Server", "TLSSocket"],
	"node:dgram": ["createSocket", "Socket"],
	"node:http2": ["connect", "createServer", "createSecureServer"],
};
/** Libraries that are network clients, by package name. */
const clients = ["ioredis", "nodemailer", "undici", "ws", "node-fetch", "axios", "got"];
/** Globals that reach the network when no local binding of the name hides them. */
const globals = ["fetch", "WebSocket", "EventSource"];

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
	],
	redis: ["ioredis"],
	smtp: ["node:net connect", "node:tls connect", "nodemailer"],
};

const nodeName = (specifier: string) =>
	specifier.startsWith("node:") ? specifier : `node:${specifier}`;
const clientOf = (specifier: string) =>
	clients.find((c) => specifier === c || specifier.startsWith(`${c}/`));

/** Each place a file reaches the network, as `module name`, `module` (imported whole), a client, or a global. */
export function reachesOf(path: string): string[] {
	const file = ts.createSourceFile(path, readFileSync(path, "utf8"), ts.ScriptTarget.Latest, true);
	const found: string[] = [];
	const bound = new Set<string>();
	const visit = (node: ts.Node): void => {
		if ((ts.isParameter(node) || ts.isVariableDeclaration(node)) && ts.isIdentifier(node.name)) {
			bound.add(node.name.text);
		}
		if (ts.isFunctionDeclaration(node) && node.name) bound.add(node.name.text);
		ts.forEachChild(node, visit);
	};
	visit(file);
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
	const calls = (node: ts.Node): void => {
		const callee =
			ts.isCallExpression(node) || ts.isNewExpression(node) ? node.expression : undefined;
		if (
			callee &&
			ts.isIdentifier(callee) &&
			globals.includes(callee.text) &&
			!bound.has(callee.text)
		) {
			found.push(callee.text);
		}
		ts.forEachChild(node, calls);
	};
	calls(file);
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
