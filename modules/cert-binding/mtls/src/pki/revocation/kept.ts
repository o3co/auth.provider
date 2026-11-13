import type * as pkijs from "pkijs";

type Entry<T> = { readonly value: T; readonly until: number; readonly weight: number };

/**
 * At most `size` entries, each until its time, the oldest going first; with a `budget`, their
 * weights together at most its `most` too, and one weighing more alone is not kept.
 */
export function expiring<T>(
	size: number,
	now: () => number,
	budget?: { readonly most: number; readonly weigh: (value: T) => number },
) {
	const entries = new Map<string, Entry<T>>();
	let weight = 0;
	const drop = (key: string) => {
		weight -= entries.get(key)?.weight ?? 0;
		entries.delete(key);
	};
	return {
		get: (key: string) => {
			const entry = entries.get(key);
			if (!entry || entry.until > now()) return entry;
			drop(key);
			return undefined;
		},
		set: (key: string, value: T, until: number) => {
			drop(key);
			const heavy = budget?.weigh(value) ?? 0;
			if (budget && heavy > budget.most) return;
			while (entries.size >= size || (budget && weight + heavy > budget.most)) {
				drop(entries.keys().next().value as string);
			}
			entries.set(key, { value, until, weight: heavy });
			weight += heavy;
		},
	};
}

export type Expiring<T> = ReturnType<typeof expiring<T>>;

/** A key's lookup, run alone. */
export type Alone = <T>(key: string, look: () => Promise<T>) => Promise<T>;

export function oneAtATime(): Alone {
	// One lookup of a key at a time, so none overwrites what another kept; a caller waits, then looks again.
	const running = new Map<string, Promise<unknown>>();
	return async function alone<T>(key: string, look: () => Promise<T>): Promise<T> {
		let other = running.get(key);
		// Lookups report failures as values, so a rejection here is a bug and is passed on as it is.
		while (other) {
			await other;
			other = running.get(key);
		}
		const mine = look();
		running.set(key, mine);
		try {
			return await mine;
		} finally {
			running.delete(key);
		}
	};
}

const hex = (bytes: Uint8Array) =>
	Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/** A certificate by its issuer's name and key, as the certificate names it, and its serial. */
export const keyOf = (cert: pkijs.Certificate, issuer: pkijs.Certificate) =>
	[
		new Uint8Array(cert.issuer.toSchema().toBER(false)),
		issuer.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView,
		cert.serialNumber.valueBlock.valueHexView,
	]
		.map(hex)
		.join(":");
