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
