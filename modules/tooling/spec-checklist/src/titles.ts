import ts from "typescript";
import { idLike, itemId } from "./ids.ts";

const runners = new Set(["it", "test", "describe"]);
const modifiers = new Set([
	"each",
	"for",
	"runIf",
	"skipIf",
	"only",
	"skip",
	"todo",
	"concurrent",
	"sequential",
	"fails",
	"shuffle",
]);

/** Whether a call's callee is `it`, `test` or `describe`, through modifiers and the calls they return. */
function isRunner(callee: ts.Expression): boolean {
	let at = callee;
	for (;;) {
		if (ts.isIdentifier(at)) return runners.has(at.text);
		if (ts.isPropertyAccessExpression(at) && modifiers.has(at.name.text)) at = at.expression;
		else if (ts.isCallExpression(at)) at = at.expression;
		else return false;
	}
}

export interface Title {
	readonly title: string;
	readonly ids: readonly string[];
}

/**
 * The titles that name items, each with the IDs written in brackets in it, and every ID written
 * anywhere else (`stray`): outside a title, in a title but not in brackets, or anywhere in a file that
 * holds no tests. A title is the first argument of `it`, `test` or `describe`, a string with no
 * substitution.
 */
export function titlesIn(
	source: string,
	holdsTests: boolean,
): { titles: Title[]; stray: string[] } {
	const spans: { start: number; end: number; text: string }[] = [];
	if (holdsTests) {
		const file = ts.createSourceFile("t.ts", source, ts.ScriptTarget.Latest, true);
		const visit = (node: ts.Node) => {
			const [first] = ts.isCallExpression(node) ? node.arguments : [];
			if (
				ts.isCallExpression(node) &&
				first &&
				(ts.isStringLiteral(first) || ts.isNoSubstitutionTemplateLiteral(first)) &&
				isRunner(node.expression)
			)
				spans.push({ start: first.getStart(file), end: first.end, text: first.text });
			ts.forEachChild(node, visit);
		};
		visit(file);
	}
	const stray: string[] = [];
	const titled = new Map<number, string[]>();
	for (const m of source.matchAll(idLike)) {
		const at = m.index;
		const span = spans.findIndex((s) => s.start <= at && at < s.end);
		const bracketed = source[at - 1] === "[" && source[at + m[0].length] === "]";
		if (span >= 0) titled.set(span, titled.get(span) ?? []);
		if (span >= 0 && bracketed && itemId.test(m[0])) titled.get(span)?.push(m[0]);
		else stray.push(m[0]);
	}
	const titles = [...titled]
		.sort(([a], [b]) => a - b)
		.map(([k, ids]) => ({ title: spans[k]?.text ?? "", ids }));
	return { titles, stray };
}
