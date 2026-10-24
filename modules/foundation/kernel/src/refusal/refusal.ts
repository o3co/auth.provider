export interface Refusal {
	readonly where: string;
	readonly reason: string;
}

/** The mark a refused boot carries, the same in every copy of the kernel a bundle may hold. */
const bootRefusedMark = Symbol.for("@mod/kernel.boot-refused");

/** Raised by assembly when anything refuses; nothing is served after it. */
export class BootRefused extends Error {
	readonly refusals: readonly Refusal[];
	readonly [bootRefusedMark] = true;
	constructor(refusals: readonly Refusal[]) {
		super(`boot refused (${refusals.length})`);
		this.name = "BootRefused";
		this.refusals = Object.freeze([...refusals]);
	}
	/** Whether `error` is a refused boot, by its mark rather than its class, so two copies of the kernel agree. */
	static is(error: unknown): error is BootRefused {
		return (
			typeof error === "object" &&
			error !== null &&
			(error as { readonly [bootRefusedMark]?: unknown })[bootRefusedMark] === true
		);
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
 * The refusal a thrown value is, read once and never throwing: one marked, whose where and reason
 * are each a diagnostic line; none for any other, or one whose reading throws.
 */
export function buildRefusalOf(error: unknown): Refusal | undefined {
	try {
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
	} catch {
		return undefined;
	}
}

/** Thrown by refuse and refuseAll inside a factory; assembly records its refusals. Never leaves the kernel. */
export class RefusalSignal extends Error {
	readonly refusals: readonly Refusal[];
	constructor(refusals: readonly Refusal[]) {
		super(`${refusals.length} refusal(s)`);
		this.refusals = refusals;
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

/** Whether `error` is an outage, by its mark rather than its class, so two copies of the kernel agree. */
export function isUnavailable(error: unknown): error is Unavailable {
	return (
		typeof error === "object" &&
		error !== null &&
		(error as { readonly [unavailableMark]?: unknown })[unavailableMark] === true
	);
}
