import ts from "typescript";
import { idCandidate, itemId } from "./ids.ts";

const runners = new Set(["it", "test", "describe"]);
/** Modifiers that take the title themselves. */
const direct = new Set(["only", "skip", "todo", "concurrent", "sequential", "fails", "shuffle"]);
/** Modifiers that take a table or a condition, and return what takes the title. */
const factories = new Set(["each", "for", "runIf", "skipIf"]);
/** Of those, the ones that also take their table as a tagged template. */
const tables = new Set(["each", "for"]);

/**
 * A runner, through modifiers that take the title and the calls of those that return what does,
 * a table given as a tagged template among them.
 */
function isChain(e: ts.Expression): boolean {
	if (ts.isIdentifier(e)) return runners.has(e.text);
	if (ts.isPropertyAccessExpression(e)) return direct.has(e.name.text) && isChain(e.expression);
	if (ts.isTaggedTemplateExpression(e))
		return (
			ts.isPropertyAccessExpression(e.tag) &&
			tables.has(e.tag.name.text) &&
			isChain(e.tag.expression)
		);
	if (ts.isCallExpression(e))
		return (
			ts.isPropertyAccessExpression(e.expression) &&
			factories.has(e.expression.name.text) &&
			isChain(e.expression.expression)
		);
	return false;
}

export interface Title {
	readonly title: string;
	readonly ids: readonly string[];
	/** Its suites' titles, outermost first, then its own; a suite's title that is no plain string is `null`. */
	readonly path: readonly (string | null)[];
	/** Whether it is a suite's title (`describe`), which the tests inside it meet. */
	readonly suite: boolean;
}

interface Literal {
	readonly start: number;
	readonly end: number;
	readonly text: string;
	readonly title: boolean;
	readonly path: readonly (string | null)[];
	readonly suite: boolean;
}

/** The runner a chain of modifiers starts from. */
function runnerOf(e: ts.Expression): string {
	if (ts.isIdentifier(e)) return e.text;
	if (ts.isPropertyAccessExpression(e)) return runnerOf(e.expression);
	if (ts.isTaggedTemplateExpression(e)) return runnerOf(e.tag);
	if (ts.isCallExpression(e)) return runnerOf(e.expression);
	return "";
}

/** Every string and template part in a source, decoded, and whether it is a test's title. */
function literalsOf(source: string, holdsTests: boolean): Literal[] {
	const file = ts.createSourceFile("t.ts", source, ts.ScriptTarget.Latest, true);
	const titles = new Map<ts.Node, { path: (string | null)[]; suite: boolean }>();
	const literals: Literal[] = [];
	// The titles of the suites the visit is inside, outermost first.
	const suites: (string | null)[] = [];
	const visit = (node: ts.Node) => {
		const [first] = ts.isCallExpression(node) ? node.arguments : [];
		const runner =
			holdsTests && ts.isCallExpression(node) && isChain(node.expression)
				? runnerOf(node.expression)
				: "";
		const plain = first && ts.isStringLiteral(first) ? first : undefined;
		if (runner && plain)
			titles.set(plain, { path: [...suites, plain.text], suite: runner === "describe" });
		if (runner === "describe") {
			suites.push(plain ? plain.text : null);
			ts.forEachChild(node, visit);
			suites.pop();
			return;
		}
		if (
			ts.isStringLiteral(node) ||
			ts.isNoSubstitutionTemplateLiteral(node) ||
			ts.isTemplateHead(node) ||
			ts.isTemplateMiddle(node) ||
			ts.isTemplateTail(node)
		)
			literals.push({
				start: node.getStart(file),
				end: node.end,
				text: node.text,
				title: titles.has(node),
				path: titles.get(node)?.path ?? [],
				suite: titles.get(node)?.suite ?? false,
			});
		ts.forEachChild(node, visit);
	};
	visit(file);
	return literals;
}

/**
 * The titles that name items, each with the IDs written in brackets in it, and every ID written
 * anywhere else (`stray`): outside a title, in a title but not in brackets or malformed, or anywhere
 * in a file that holds no tests. A title is a plain string, the first argument of a call of `it`,
 * `test` or `describe` that takes it. Strings are read decoded; the rest of the source as written.
 */
export function titlesIn(
	source: string,
	holdsTests: boolean,
): { titles: Title[]; stray: string[] } {
	const literals = literalsOf(source, holdsTests);
	const found: { at: number; id: string }[] = [];
	const titles: { at: number; title: Title }[] = [];
	for (const l of literals) {
		const ids: string[] = [];
		const candidates = [...l.text.matchAll(idCandidate)];
		for (const m of candidates) {
			const bracketed = l.text[m.index - 1] === "[" && l.text[m.index + m[0].length] === "]";
			if (l.title && bracketed && itemId.test(m[0])) ids.push(m[0]);
			else found.push({ at: l.start + m.index, id: m[0] });
		}
		if (l.title && candidates.length > 0)
			titles.push({ at: l.start, title: { title: l.text, ids, path: l.path, suite: l.suite } });
	}
	let rest = source;
	for (const l of literals)
		rest = rest.slice(0, l.start) + " ".repeat(l.end - l.start) + rest.slice(l.end);
	for (const m of rest.matchAll(idCandidate)) found.push({ at: m.index, id: m[0] });
	return {
		titles: titles.sort((a, b) => a.at - b.at).map((t) => t.title),
		stray: found.sort((a, b) => a.at - b.at).map((f) => f.id),
	};
}
