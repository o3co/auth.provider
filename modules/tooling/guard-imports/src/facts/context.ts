import ts from "typescript";

/** Whether a node is in an ambient context, where nothing runs: a declaration file, or inside a `declare`d declaration (the one test edges and names ask). */
export function ambient(node: ts.Node): boolean {
	if (node.getSourceFile().isDeclarationFile) return true;
	for (
		let at: ts.Node | undefined = node;
		at !== undefined && !ts.isSourceFile(at);
		at = at.parent
	) {
		const modifiers = ts.canHaveModifiers(at) ? (ts.getModifiers(at) ?? []) : [];
		if (modifiers.some((m) => m.kind === ts.SyntaxKind.DeclareKeyword)) return true;
	}
	return false;
}
