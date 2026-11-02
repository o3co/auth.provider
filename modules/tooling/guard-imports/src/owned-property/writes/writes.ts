import ts from "typescript";

/** Whether a type holds a type parameter anywhere: in a union or intersection, a template, a mapped string, or as one. */
const holdsTypeParameter = (type: ts.Type): boolean => {
	const deferred =
		ts.TypeFlags.TypeParameter |
		ts.TypeFlags.Index |
		ts.TypeFlags.IndexedAccess |
		ts.TypeFlags.Conditional |
		ts.TypeFlags.Substitution;
	if (type.flags & deferred) return true;
	if (type.isUnionOrIntersection()) return type.types.some(holdsTypeParameter);
	if (type.flags & ts.TypeFlags.TemplateLiteral)
		return (type as ts.TemplateLiteralType).types.some(holdsTypeParameter);
	if (type.flags & ts.TypeFlags.StringMapping)
		return holdsTypeParameter((type as ts.StringMappingType).type);
	return false;
};

/**
 * Whether a key may be the owned property's name: by name, or by a computed key whose type that name
 * fits (a union, a template, a mapped string or a string of no known value alike). A key whose type
 * holds a type parameter is read by what it may be bound to: its constraint, unknown for a bare one.
 */
const namesOwned = (checker: ts.TypeChecker, name: ts.PropertyName | undefined, owned: string) => {
	if (name === undefined) return false;
	if (!ts.isComputedPropertyName(name)) {
		return (ts.isIdentifier(name) || ts.isStringLiteralLike(name)) && name.text === owned;
	}
	return keyNames(checker, name.expression, owned);
};

/** Whether a key written as an expression (a computed key, an element access) may be the owned name. */
const keyNames = (checker: ts.TypeChecker, expression: ts.Expression, owned: string) => {
	const key = checker.getTypeAtLocation(expression);
	const literal = checker.getStringLiteralType(owned);
	if (holdsTypeParameter(key)) {
		const constraint = checker.getBaseConstraintOfType(key);
		return constraint === undefined || checker.isTypeAssignableTo(literal, constraint);
	}
	return checker.isTypeAssignableTo(literal, key);
};

/** Whether an operator writes its left side: `=` and every compound assignment (`+=`, `??=`, …). */
const assigns = (kind: ts.SyntaxKind) =>
	kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment;

/** The type of the value a property is written with: its initializer, its shorthand name, or its getter's return. */
const writtenType = (checker: ts.TypeChecker, property: ts.ObjectLiteralElementLike) => {
	if (ts.isPropertyAssignment(property)) return checker.getTypeAtLocation(property.initializer);
	if (ts.isShorthandPropertyAssignment(property)) return checker.getTypeAtLocation(property.name);
	if (ts.isGetAccessorDeclaration(property)) {
		const signature = checker.getSignatureFromDeclaration(property);
		return signature && checker.getReturnTypeOfSignature(signature);
	}
	return undefined;
};

/** How a write is judged: whether a name or key may be the property's, and whether what it writes is its type. */
export interface Reading {
	readonly names: (name: ts.PropertyName | undefined) => boolean;
	readonly keys: (key: ts.Expression) => boolean;
	readonly literal: (element: ts.ObjectLiteralElementLike) => boolean;
	readonly target: (access: ts.PropertyAccessExpression | ts.ElementAccessExpression) => boolean;
	readonly member: (written: ts.Node) => boolean;
}

/**
 * Whether a node is written to: the left of an assignment, the head of a `for … of` or `for … in`,
 * or a place inside a destructuring pattern that is.
 */
const isTarget = (node: ts.Node): boolean => {
	const parent = node.parent;
	if (parent === undefined) return false;
	if (ts.isParenthesizedExpression(parent)) return isTarget(parent);
	if (ts.isBinaryExpression(parent))
		return parent.left === node && assigns(parent.operatorToken.kind);
	if (ts.isForOfStatement(parent) || ts.isForInStatement(parent))
		return parent.initializer === node;
	if (ts.isPropertyAssignment(parent))
		return parent.initializer === node && isTarget(parent.parent);
	if (ts.isSpreadElement(parent) || ts.isSpreadAssignment(parent)) return isTarget(parent.parent);
	if (ts.isArrayLiteralExpression(parent)) return isTarget(parent);
	return false;
};

/**
 * The lines of a source where it writes the owned property, as `reading` judges: an object literal's
 * property (a destructuring pattern being no literal, its own keys write locals), an access to the
 * property written to, directly, compounded or as a pattern's target, a class field initialised
 * under its name, and a constructor's parameter property of that name.
 */
export function writesIn(source: ts.SourceFile, reading: Reading): number[] {
	const lines: number[] = [];
	const at = (node: ts.Node) =>
		lines.push(source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1);
	const visit = (node: ts.Node): void => {
		if (ts.isObjectLiteralExpression(node)) {
			if (!isTarget(node)) {
				for (const element of node.properties) {
					if (reading.names(element.name) && reading.literal(element)) at(element);
				}
			}
		} else if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
			const named = ts.isPropertyAccessExpression(node)
				? ts.isIdentifier(node.name) && reading.names(node.name)
				: reading.keys(node.argumentExpression);
			if (named && isTarget(node) && reading.target(node)) at(node);
		} else if (ts.isPropertyDeclaration(node) && node.initializer !== undefined) {
			if (reading.names(node.name) && reading.member(node.initializer)) at(node);
		} else if (ts.isParameterPropertyDeclaration(node, node.parent)) {
			if (reading.names(node.name as ts.PropertyName) && reading.member(node)) at(node);
		}
		ts.forEachChild(node, visit);
	};
	visit(source);
	return lines;
}

/** A file that becomes a source once filled: a `.ts` or `.mjs` name under a suffix of its own. */
export const isTemplate = (file: string) => /\.(?:ts|mjs)\.[^./]+$/.test(file);

/** The typed reading: a write counts where its value, `undefined` aside, may be of `wanted`, the property's type. */
export function typedReading(checker: ts.TypeChecker, wanted: ts.Type, owned: string): Reading {
	const holds = (value: ts.Type | undefined) => {
		if (value === undefined) return false;
		const held = checker.getNonNullableType(value);
		if (held.flags & (ts.TypeFlags.Any | ts.TypeFlags.Never | ts.TypeFlags.Unknown)) return false;
		// A type parameter counts where the property's type may be bound to it (the helper writes it,
		// whoever calls), or where it is of that type itself.
		if (holdsTypeParameter(held)) {
			const constraint = checker.getBaseConstraintOfType(held);
			if (constraint === undefined || checker.isTypeAssignableTo(wanted, constraint)) return true;
		}
		return checker.isTypeAssignableTo(held, wanted);
	};
	return {
		names: (name) => namesOwned(checker, name, owned),
		keys: (key) => keyNames(checker, key, owned),
		literal: (element) => holds(writtenType(checker, element)),
		// A target is judged by its own type, and a direct assignment by its value's too.
		target: (access) => {
			if (holds(checker.getTypeAtLocation(access))) return true;
			// A direct assignment, its target parenthesised or not, is judged by its value too.
			let at: ts.Node = access;
			while (ts.isParenthesizedExpression(at.parent)) at = at.parent;
			return (
				ts.isBinaryExpression(at.parent) &&
				at.parent.left === at &&
				holds(checker.getTypeAtLocation(at.parent.right))
			);
		},
		member: (written) => holds(checker.getTypeAtLocation(written)),
	};
}

/** The reading by name alone, for a template, whose values have no type: a key of another literal name is not the property. */
export function byNameReading(owned: string): Reading {
	const keys = (key: ts.Expression) =>
		!(ts.isStringLiteralLike(key) || ts.isNumericLiteral(key)) || key.text === owned;
	return {
		names: (name) => {
			if (name === undefined) return false;
			if (!ts.isComputedPropertyName(name)) {
				return (ts.isIdentifier(name) || ts.isStringLiteralLike(name)) && name.text === owned;
			}
			return keys(name.expression);
		},
		keys,
		literal: () => true,
		target: () => true,
		member: () => true,
	};
}
