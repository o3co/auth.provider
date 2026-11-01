import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { type Edge, type FileFacts, lexicalAnalysis, type Target } from "../facts.ts";

/** A workspace of files under a fresh directory (`<root>` in a text naming it), links among them, and the facts of the first file. */
export function factsFor(
	files: Readonly<Record<string, string>>,
	links: Readonly<Record<string, string>> = {},
): { facts: FileFacts; root: string } {
	const root = realpathSync(mkdtempSync(join(tmpdir(), "facts-")));
	for (const [file, text] of Object.entries(files)) {
		mkdirSync(join(root, dirname(file)), { recursive: true });
		writeFileSync(join(root, file), text.replaceAll("<root>", root));
	}
	for (const [link, to] of Object.entries(links)) {
		mkdirSync(join(root, dirname(link)), { recursive: true });
		symlinkSync(join(root, to), join(root, link));
	}
	const paths = Object.keys(files).map((file) => join(root, file));
	const first = paths[0] as string;
	return { facts: lexicalAnalysis(paths).factsOf(first), root };
}

/** A target as one line, a file's path from the root. */
export function targetLine(target: Target, root: string): string {
	if (target.kind === "builtin") return `builtin ${target.name}`;
	if (target.kind === "package")
		return `package ${target.name}${target.subpath ? ` /${target.subpath}` : ""}`;
	if (target.kind === "file") {
		const identity = new URL(target.url);
		return `file ${relative(root, target.path)}${identity.search}${identity.hash}`;
	}
	const where = target.path === undefined ? "" : ` ${relative(root, target.path)}`;
	const fragment = target.fragment === undefined ? "" : ` "${target.fragment}"`;
	return `unresolved ${target.reason}${fragment}${where}`;
}

/** An edge as one line: its form, specifier, whether it loads, its target and its bindings. */
export function edgeLine(edge: Edge, root: string): string {
	const specifier = edge.specifier.text ?? `${edge.specifier.fragment ?? ""}…`;
	const bindings = edge.bindings.map(
		(b) =>
			`${b.form}:${b.imported}${b.local ? `>${b.local.text}` : ""}${b.exported ? `=>${b.exported}` : ""}${b.typeOnly ? "(type)" : ""}`,
	);
	const loader = edge.loader ? ` [${edge.loader}]` : "";
	return [
		`${edge.form}${loader} ${specifier} ${edge.loads ? "loads" : "-"} → ${targetLine(edge.target, root)}`,
		...(bindings.length > 0 ? [`{${bindings.join(" ")}}`] : []),
	].join(" ");
}

/** Each use of a name in the file, as its role and binding. */
export function usesOf(facts: FileFacts, name: string): string[] {
	return facts.references
		.filter((r) => r.node.text === name)
		.map((r) => {
			const b = r.binding;
			const bound =
				b === undefined ? "" : b.kind === "imported" ? ` imported ${b.name}` : ` ${b.kind}`;
			return `${r.role}${bound}`;
		});
}
