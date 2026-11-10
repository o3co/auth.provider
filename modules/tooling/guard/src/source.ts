import { parse } from "@mod/guard-imports";
import ts from "typescript";

export interface LineCounts {
	readonly code: number;
	readonly comment: number;
}

function commentRanges(file: ts.SourceFile): ts.CommentRange[] {
	const text = file.text;
	const ranges = new Map<number, ts.CommentRange>();
	const collect = (list: ts.CommentRange[] | undefined) => {
		for (const range of list ?? []) ranges.set(range.pos, range);
	};
	const visit = (node: ts.Node): void => {
		collect(ts.getLeadingCommentRanges(text, node.getFullStart()));
		collect(ts.getTrailingCommentRanges(text, node.getEnd()));
		ts.forEachChild(node, visit);
	};
	visit(file);
	collect(ts.getLeadingCommentRanges(text, file.endOfFileToken.getFullStart()));
	return [...ranges.values()];
}

/** The text of every comment, taken from the syntax tree (so never from inside a string). */
export function commentsOf(path: string): string[] {
	const file = parse(path);
	return commentRanges(file).map((range) => file.text.slice(range.pos, range.end));
}

/**
 * Non-blank lines, and lines that carry a comment, taken from the syntax tree; a comment that
 * starts at one of `leftOut` carries none.
 */
export function countLines(path: string, leftOut: ReadonlySet<number> = new Set()): LineCounts {
	const file = parse(path);
	const code = file.text.split("\n").filter((line) => line.trim() !== "").length;
	const lines = new Set<number>();
	for (const range of commentRanges(file).filter((r) => !leftOut.has(r.pos))) {
		const first = file.getLineAndCharacterOfPosition(range.pos).line;
		const last = file.getLineAndCharacterOfPosition(range.end).line;
		for (let line = first; line <= last; line++) lines.add(line);
	}
	return { code, comment: lines.size };
}

/** Places that read the host's clock directly, by the expression read. */
export function clockReads(path: string): string[] {
	const found: string[] = [];
	const visit = (node: ts.Node): void => {
		if (
			ts.isCallExpression(node) &&
			ts.isPropertyAccessExpression(node.expression) &&
			ts.isIdentifier(node.expression.expression) &&
			((node.expression.expression.text === "Date" && node.expression.name.text === "now") ||
				(node.expression.expression.text === "performance" && node.expression.name.text === "now"))
		) {
			found.push(`${node.expression.expression.text}.now()`);
		}
		if (
			ts.isNewExpression(node) &&
			ts.isIdentifier(node.expression) &&
			node.expression.text === "Date" &&
			(node.arguments?.length ?? 0) === 0
		) {
			found.push("new Date()");
		}
		ts.forEachChild(node, visit);
	};
	visit(parse(path));
	return found;
}

/** node:crypto's functions that draw random values or make keys. */
const nodeRandom = new Set([
	"randomBytes",
	"randomFill",
	"randomFillSync",
	"randomInt",
	"randomUUID",
	"getRandomValues",
	"generateKey",
	"generateKeySync",
	"generateKeyPair",
	"generateKeyPairSync",
	"generatePrime",
	"generatePrimeSync",
]);
const webRandom = new Set([
	"crypto.getRandomValues",
	"crypto.randomUUID",
	"crypto.subtle.generateKey",
]);

/** A callee made only of names and dots, as written. */
function dotted(node: ts.Expression): string | undefined {
	if (ts.isIdentifier(node)) return node.text;
	if (!ts.isPropertyAccessExpression(node)) return undefined;
	const left = dotted(node.expression);
	return left === undefined ? undefined : `${left}.${node.name.text}`;
}

/** Places that draw randomness directly: Math.random, node:crypto's random and key functions, Web Crypto. */
export function randomReads(path: string): string[] {
	const found: string[] = [];
	const whole = new Map<string, string>();
	const visit = (node: ts.Node): void => {
		const from =
			ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)
				? node.moduleSpecifier.text
				: "";
		if ((from === "node:crypto" || from === "crypto") && ts.isImportDeclaration(node)) {
			const clause = node.importClause;
			const named = clause?.namedBindings;
			if (clause?.name) whole.set(clause.name.text, from);
			if (named && ts.isNamespaceImport(named)) whole.set(named.name.text, from);
			for (const element of named && ts.isNamedImports(named) ? named.elements : []) {
				const name = (element.propertyName ?? element.name).text;
				if (nodeRandom.has(name)) found.push(`${name} from ${from}`);
			}
		}
		const callee = ts.isCallExpression(node) ? dotted(node.expression) : undefined;
		const [receiver, ...rest] = callee?.split(".") ?? [];
		const web = callee?.replace(/^globalThis\./, "");
		if (callee === "Math.random") found.push("Math.random()");
		else if (
			receiver &&
			whole.has(receiver) &&
			rest.length === 1 &&
			nodeRandom.has(rest[0] ?? "")
		) {
			found.push(`${rest[0]} from ${whole.get(receiver)}`);
		} else if (web && webRandom.has(web)) found.push(`${callee}()`);
		ts.forEachChild(node, visit);
	};
	visit(parse(path));
	return found;
}

const branching: Partial<Record<ts.SyntaxKind, string>> = {
	[ts.SyntaxKind.IfStatement]: "if",
	[ts.SyntaxKind.SwitchStatement]: "switch",
	[ts.SyntaxKind.ForStatement]: "for",
	[ts.SyntaxKind.ForInStatement]: "for",
	[ts.SyntaxKind.ForOfStatement]: "for",
	[ts.SyntaxKind.WhileStatement]: "while",
	[ts.SyntaxKind.DoStatement]: "do",
	[ts.SyntaxKind.ConditionalExpression]: "?:",
};

/** Operators that choose what runs or what is taken, as a branch does. */
const choosing: Partial<Record<ts.SyntaxKind, string>> = {
	[ts.SyntaxKind.AmpersandAmpersandToken]: "&&",
	[ts.SyntaxKind.BarBarToken]: "||",
	[ts.SyntaxKind.QuestionQuestionToken]: "??",
	[ts.SyntaxKind.AmpersandAmpersandEqualsToken]: "&&=",
	[ts.SyntaxKind.BarBarEqualsToken]: "||=",
	[ts.SyntaxKind.QuestionQuestionEqualsToken]: "??=",
};

/** Calls that walk a collection with a function, as a loop does. */
const walking = new Set([
	"map",
	"flatMap",
	"filter",
	"reduce",
	"reduceRight",
	"forEach",
	"some",
	"every",
	"find",
	"findIndex",
	"findLast",
	"findLastIndex",
	"sort",
	"toSorted",
]);

/** The method a call names, when it is a call on a property. */
const calledMethod = (node: ts.Node) =>
	ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)
		? node.expression.name.text
		: undefined;

/**
 * The branches and loops in a file, by the word that makes each; choosing operators and calls
 * that walk a collection count too.
 */
export function branchesOf(path: string): string[] {
	const found: string[] = [];
	const visit = (node: ts.Node): void => {
		const method = calledMethod(node);
		const word = ts.isBinaryExpression(node)
			? choosing[node.operatorToken.kind]
			: method !== undefined && walking.has(method)
				? `.${method}()`
				: branching[node.kind];
		if (word) found.push(word);
		ts.forEachChild(node, visit);
	};
	visit(parse(path));
	return found;
}
