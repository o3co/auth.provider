/**
 * GitHub Actions' expressions, as far as a run's `github` context decides them: literals, `!`, `&&`,
 * `||`, `==`, `!=`, parentheses and `startsWith`, `endsWith`, `contains`. Anything else (another
 * context, a status function, a function or syntax not here) is `unknown`, never guessed.
 */

/** The parts of a run's `github` context an expression here may read. */
export interface RunContext {
	readonly event_name: string;
	readonly ref: string;
	readonly base_ref: string;
}

export type Value = string | number | boolean | null;

/** What could not be decided, and why. */
export interface Unknown {
	readonly unknown: string;
}

const isUnknown = (v: Value | Unknown): v is Unknown =>
	typeof v === "object" && v !== null && "unknown" in v;

/** GitHub's truthiness: `false`, `0`, `-0`, `''`, `null` and `NaN` are false. */
export const truthy = (v: Value): boolean =>
	!(
		v === false ||
		v === null ||
		v === "" ||
		(typeof v === "number" && (v === 0 || Number.isNaN(v)))
	);

const toNumber = (v: Value): number =>
	v === null
		? 0
		: typeof v === "boolean"
			? Number(v)
			: typeof v === "number"
				? v
				: v.trim() === ""
					? 0
					: Number(v);

/** GitHub's `==`: strings without regard to case, other kinds as numbers. */
const equal = (a: Value, b: Value): boolean =>
	typeof a === "string" && typeof b === "string"
		? a.toLowerCase() === b.toLowerCase()
		: typeof a === typeof b
			? a === b
			: toNumber(a) === toNumber(b);

const asText = (v: Value): string => (v === null ? "" : String(v));

type Token =
	| { readonly kind: "string"; readonly value: string }
	| { readonly kind: "number"; readonly value: number }
	| { readonly kind: "word"; readonly value: string }
	| { readonly kind: "op"; readonly value: string };

function tokens(source: string): Token[] {
	const out: Token[] = [];
	let i = 0;
	while (i < source.length) {
		const c = source[i] as string;
		if (/\s/.test(c)) {
			i++;
		} else if (c === "'") {
			let text = "";
			i++;
			for (;;) {
				if (i >= source.length) throw new Error("an unclosed string");
				if (source[i] === "'" && source[i + 1] === "'") {
					text += "'";
					i += 2;
				} else if (source[i] === "'") {
					i++;
					break;
				} else {
					text += source[i++];
				}
			}
			out.push({ kind: "string", value: text });
		} else if (/[0-9]/.test(c)) {
			const m = /^[0-9]+(\.[0-9]+)?/.exec(source.slice(i)) as RegExpExecArray;
			out.push({ kind: "number", value: Number(m[0]) });
			i += m[0].length;
		} else if (/[A-Za-z_]/.test(c)) {
			const m = /^[A-Za-z_][A-Za-z0-9_.-]*/.exec(source.slice(i)) as RegExpExecArray;
			out.push({ kind: "word", value: m[0] });
			i += m[0].length;
		} else {
			const two = source.slice(i, i + 2);
			if (["==", "!=", "&&", "||"].includes(two)) {
				out.push({ kind: "op", value: two });
				i += 2;
			} else if ("!(),".includes(c)) {
				out.push({ kind: "op", value: c });
				i++;
			} else {
				throw new Error(`${JSON.stringify(c)} is no syntax read here`);
			}
		}
	}
	return out;
}

/** Evaluates one expression (the text inside `${{ }}`, or an `if:` written without it) in the context given. */
export function evaluate(source: string, context: RunContext): Value | Unknown {
	let list: Token[];
	try {
		list = tokens(source);
	} catch (error) {
		return { unknown: (error as Error).message };
	}
	let at = 0;
	const peek = () => list[at];
	const take = (value: string) => {
		const t = list[at];
		if (t?.kind !== "op" || t.value !== value) throw new Error(`${value} expected`);
		at++;
	};

	const github: Record<string, Value> = {
		event_name: context.event_name,
		ref: context.ref,
		base_ref: context.base_ref,
	};
	const functions: Record<string, (args: Value[]) => Value> = {
		startswith: ([a, b]) =>
			asText(a ?? null)
				.toLowerCase()
				.startsWith(asText(b ?? null).toLowerCase()),
		endswith: ([a, b]) =>
			asText(a ?? null)
				.toLowerCase()
				.endsWith(asText(b ?? null).toLowerCase()),
		contains: ([a, b]) =>
			asText(a ?? null)
				.toLowerCase()
				.includes(asText(b ?? null).toLowerCase()),
	};

	const or = (): Value | Unknown => {
		let left = and();
		while (peek()?.kind === "op" && peek()?.value === "||") {
			at++;
			const right = and();
			left = !isUnknown(left) && truthy(left) ? left : isUnknown(left) ? left : right;
		}
		return left;
	};
	const and = (): Value | Unknown => {
		let left = compare();
		while (peek()?.kind === "op" && peek()?.value === "&&") {
			at++;
			const right = compare();
			left = !isUnknown(left) && !truthy(left) ? left : isUnknown(left) ? left : right;
		}
		return left;
	};
	const compare = (): Value | Unknown => {
		const left = not();
		const t = peek();
		if (t?.kind === "op" && (t.value === "==" || t.value === "!=")) {
			at++;
			const right = not();
			if (isUnknown(left)) return left;
			if (isUnknown(right)) return right;
			return t.value === "==" ? equal(left, right) : !equal(left, right);
		}
		return left;
	};
	// `!` binds tighter than `==`, as GitHub reads it.
	const not = (): Value | Unknown => {
		if (peek()?.kind === "op" && peek()?.value === "!") {
			at++;
			const v = not();
			return isUnknown(v) ? v : !truthy(v);
		}
		return primary();
	};
	const primary = (): Value | Unknown => {
		const t = list[at++];
		if (t === undefined) throw new Error("an expression ends too soon");
		if (t.kind === "string" || t.kind === "number") return t.value;
		if (t.kind === "op") {
			if (t.value !== "(") throw new Error(`${t.value} is out of place`);
			const v = or();
			take(")");
			return v;
		}
		const word = t.value;
		if (peek()?.kind === "op" && peek()?.value === "(") {
			at++;
			const args: (Value | Unknown)[] = [];
			if (!(peek()?.kind === "op" && peek()?.value === ")")) {
				args.push(or());
				while (peek()?.kind === "op" && peek()?.value === ",") {
					at++;
					args.push(or());
				}
			}
			take(")");
			const f = Object.hasOwn(functions, word.toLowerCase())
				? functions[word.toLowerCase()]
				: undefined;
			if (f === undefined)
				return { unknown: `${word}() is not decided by the run's github context` };
			const known = args.find(isUnknown);
			return known ?? f(args as Value[]);
		}
		if (word === "true") return true;
		if (word === "false") return false;
		if (word === "null") return null;
		const [scope, name, ...rest] = word.split(".");
		if (
			scope === "github" &&
			name !== undefined &&
			rest.length === 0 &&
			Object.hasOwn(github, name)
		) {
			return github[name] as Value;
		}
		return { unknown: `${word} is not read here` };
	};

	try {
		const value = or();
		if (at !== list.length) return { unknown: "the expression goes on past its end" };
		return value;
	} catch (error) {
		return { unknown: (error as Error).message };
	}
}

/**
 * A workflow value as GitHub reads it: an expression alone (`${{ … }}`) is evaluated, a plain value
 * is itself, and text mixing the two is unknown.
 */
export function inputOf(written: unknown, context: RunContext): Value | Unknown {
	if (written === undefined) return { unknown: "nothing written" };
	if (typeof written !== "string") {
		return written === null || typeof written === "boolean" || typeof written === "number"
			? written
			: { unknown: "no plain value" };
	}
	const whole = /^\s*\$\{\{(.*)\}\}\s*$/s.exec(written);
	if (whole) {
		const inner = whole[1] as string;
		return inner.includes("${{") || inner.includes("}}")
			? { unknown: "more than one expression" }
			: evaluate(inner, context);
	}
	return written.includes("${{") ? { unknown: "text mixed with an expression" } : written;
}

/** An `if:` as GitHub reads it: written with or without `${{ }}`. */
export function conditionOf(written: unknown, context: RunContext): Value | Unknown {
	if (typeof written === "string" && !/^\s*\$\{\{/.test(written)) return evaluate(written, context);
	return inputOf(written, context);
}

export { isUnknown };
