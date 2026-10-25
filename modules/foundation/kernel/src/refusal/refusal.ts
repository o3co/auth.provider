export interface Refusal {
	readonly where: string;
	readonly reason: string;
}

/** Whether a thrown value carries `mark`, false where reading it throws (a revoked proxy, a trap that throws). */
const marked = (error: unknown, mark: symbol): boolean =>
	readThrown(
		() =>
			typeof error === "object" &&
			error !== null &&
			(error as { readonly [key: symbol]: unknown })[mark] === true,
		false,
	);

/** The mark a refused boot carries, the same in every copy of the kernel a bundle may hold. */
const bootRefusedMark = Symbol.for("@mod/kernel.boot-refused");

/** Raised by assembly when anything refuses; nothing is served after it. */
export class BootRefused extends Error {
	readonly refusals: readonly Refusal[];
	readonly [bootRefusedMark] = true;
	constructor(refusals: readonly Refusal[]) {
		// Its own list, read one at a time: whoever gave the refusals may change them later.
		const read = refusalsIn(refusals);
		super(`boot refused (${read.length})`);
		this.name = "BootRefused";
		this.refusals = Object.freeze(read);
	}
	/** Whether `error` is a refused boot, by its mark rather than its class, so two copies of the kernel agree; it never throws. */
	static is(error: unknown): error is BootRefused {
		return marked(error, bootRefusedMark);
	}
}

/** The mark a library's refusal carries, the same in every copy of the kernel a bundle may hold. */
const buildRefusedMark = Symbol.for("@mod/kernel.build-refused");

const whereMax = 200;
const reasonMax = 500;
/** A line an operator reads as written: no control, format or line-separator character. */
const unprintable = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
const isDiagnostic = (text: unknown, max: number): text is string =>
	typeof text === "string" && text.length > 0 && text.length <= max && !unprintable.test(text);

/**
 * A refusal a library throws from inside a factory, holding no build context to refuse through:
 * assembly records its where and reason as the boot's refusal, and the operator reads them as
 * written. They are a public diagnostic, never a secret (a key, a token, a value from a request or
 * from configuration): the kernel can check their form, never what they say. Each is one line,
 * `where` 1 to 200 characters and `reason` 1 to 500, with no control or format character; any
 * other is refused with a TypeError.
 */
export class BuildRefused extends Error {
	readonly where: string;
	readonly reason: string;
	readonly [buildRefusedMark] = true;
	constructor(where: string, reason: string) {
		if (!isDiagnostic(where, whereMax) || !isDiagnostic(reason, reasonMax)) {
			throw new TypeError(
				"a refusal's where and reason are one line each, 1 to 200 and 1 to 500 characters, with no control or format character",
			);
		}
		super(`${where}: ${reason}`);
		this.name = "BuildRefused";
		this.where = where;
		this.reason = reason;
	}
	/** Whether `error` is one, by its mark rather than its class, so two copies of the kernel agree; it never throws. */
	static is(error: unknown): error is BuildRefused {
		return buildRefusalOf(error) !== undefined;
	}
}

/**
 * What `read` makes of a thrown value, or `otherwise` where reading it throws: a thrown value is
 * anyone's, its getters and proxy traps included, so the kernel reads one only through this.
 */
export function readThrown<T>(read: () => T, otherwise: T): T {
	try {
		return read();
	} catch {
		return otherwise;
	}
}

/** The error names a warn line may tell: the language's, the platform's for an abort or a timeout, and the kernel's. */
const knownKinds: ReadonlySet<string> = new Set([
	"Error",
	"TypeError",
	"RangeError",
	"SyntaxError",
	"ReferenceError",
	"EvalError",
	"URIError",
	"AggregateError",
	"AbortError",
	"TimeoutError",
	"Unavailable",
	"BuildRefused",
	"BootRefused",
]);

/**
 * The type a warn line names for a thrown value: an error's name where the kernel knows it, else
 * `Error` (a name is anyone's, a secret's too); a value's type; `unknown` where reading it throws.
 */
export const thrownKind = (error: unknown): string =>
	readThrown(() => {
		if (!(error instanceof Error)) return typeof error;
		const { name } = error;
		return typeof name === "string" && knownKinds.has(name) ? name : "Error";
	}, "unknown");

/**
 * The refusals a value holds, read as a thrown value is and never throwing: by index, one at a
 * time, each kept only where its where and reason are strings (an empty one is still words), into a list of the
 * kernel's own; a hole, a value of another shape or one whose reading throws is left out.
 */
export function refusalsIn(list: unknown): Refusal[] {
	const read: Refusal[] = [];
	const length = readThrown(() => {
		const told = (list as { readonly length?: unknown }).length;
		return typeof told === "number" && Number.isSafeInteger(told) && told > 0 ? told : 0;
	}, 0);
	for (let i = 0; i < length; i++) {
		const one = readThrown((): Refusal | undefined => {
			const item = (list as Readonly<Record<number, unknown>>)[i];
			if (typeof item !== "object" || item === null) return undefined;
			const { where, reason } = item as { readonly where?: unknown; readonly reason?: unknown };
			return typeof where === "string" && typeof reason === "string"
				? Object.freeze({ where, reason })
				: undefined;
		}, undefined);
		if (one !== undefined) read.push(one);
	}
	return read;
}

/**
 * The refusal a thrown value is, read once and never throwing: one marked, whose where and reason
 * are each a diagnostic line; none for any other, or one whose reading throws.
 */
export function buildRefusalOf(error: unknown): Refusal | undefined {
	return readThrown(() => {
		if (typeof error !== "object" || error === null) return undefined;
		const told = error as {
			readonly [buildRefusedMark]?: unknown;
			where?: unknown;
			reason?: unknown;
		};
		if (told[buildRefusedMark] !== true) return undefined;
		const { where, reason } = told;
		return isDiagnostic(where, whereMax) && isDiagnostic(reason, reasonMax)
			? { where, reason }
			: undefined;
	}, undefined);
}

/** Thrown by refuse and refuseAll inside a factory; assembly records its refusals. Never leaves the kernel. */
export class RefusalSignal extends Error {
	readonly refusals: readonly Refusal[];
	constructor(refusals: readonly Refusal[]) {
		// Its own list, read one at a time: the factory may change what it gave once it threw.
		const read = Object.freeze(refusalsIn(refusals));
		super(`${read.length} refusal(s)`);
		this.refusals = read;
	}
}

/** The mark an outage carries, the same in every copy of the kernel a bundle may hold. */
const unavailableMark = Symbol.for("@mod/kernel.unavailable");

export class Unavailable extends Error {
	readonly what: string;
	readonly [unavailableMark] = true;
	constructor(what: string) {
		super(`${what} unavailable`);
		this.name = "Unavailable";
		this.what = what;
	}
}

/** Whether `error` is an outage, by its mark rather than its class, so two copies of the kernel agree; it never throws. */
export function isUnavailable(error: unknown): error is Unavailable {
	return marked(error, unavailableMark);
}
