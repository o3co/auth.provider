export interface Refusal {
	readonly where: string;
	readonly reason: string;
}

/** Raised by assembly when anything refuses; nothing is served after it. */
export class BootRefused extends Error {
	readonly refusals: readonly Refusal[];
	constructor(refusals: readonly Refusal[]) {
		super(`boot refused (${refusals.length})`);
		this.name = "BootRefused";
		this.refusals = Object.freeze([...refusals]);
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

export class Unavailable extends Error {
	readonly what: string;
	constructor(what: string) {
		super(`${what} unavailable`);
		this.name = "Unavailable";
		this.what = what;
	}
}

export function isUnavailable(error: unknown): error is Unavailable {
	return error instanceof Unavailable;
}
