import type * as pkijs from "pkijs";

type Entry<T> = { readonly value: T; readonly until: number };

/** At most `size` entries, each until its time, the oldest going first. */
export function expiring<T>(size: number, now: () => number) {
	const entries = new Map<string, Entry<T>>();
	return {
		get: (key: string) => {
			const entry = entries.get(key);
			if (!entry || entry.until > now()) return entry;
			entries.delete(key);
			return undefined;
		},
		set: (key: string, value: T, until: number) => {
			if (entries.size >= size) entries.delete(entries.keys().next().value as string);
			entries.set(key, { value, until });
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
