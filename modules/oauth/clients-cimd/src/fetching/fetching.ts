import type { Clock } from "@mod/kernel";

/** What one fetch of an id gave: a value to keep, a refusal to remember, or a failure to forget. */
export type Fetched<T> =
	| { readonly kind: "found"; readonly value: T; readonly maxAgeMs?: number | undefined }
	| { readonly kind: "refused" }
	| { readonly kind: "failed" };

export interface Limits {
	readonly cacheMs: number;
	readonly entries: number;
	readonly refusedMs: number;
	readonly concurrent: number;
}

export interface Fetching<T> {
	/** The value kept or fetched for the id, or undefined when there is none to use now. */
	find(id: string): Promise<T | undefined>;
}

/** Keeps at most `entries` keys, dropping the one set longest ago. */
function remember<V>(map: Map<string, V>, id: string, value: V, entries: number): void {
	map.delete(id);
	if (map.size >= entries) {
		const oldest = map.keys().next();
		if (!oldest.done) map.delete(oldest.value);
	}
	map.set(id, value);
}

export function fetchingWith<T>(
	load: (id: string) => Promise<Fetched<T>>,
	limits: Limits,
	clock: Clock,
): Fetching<T> {
	const kept = new Map<string, { readonly value: T; readonly until: number }>();
	const refused = new Map<string, number>();
	const running = new Map<string, Promise<T | undefined>>();

	/** Keeps what a fetch begun at `began` gave for what is left of its time, counted from `began`. */
	const settle = (id: string, fetched: Fetched<T>, began: number): T | undefined => {
		const now = clock.now();
		if (fetched.kind === "found") {
			const until = began + Math.min(fetched.maxAgeMs ?? limits.cacheMs, limits.cacheMs);
			if (until > now) remember(kept, id, { value: fetched.value, until }, limits.entries);
			return fetched.value;
		}
		const until = began + limits.refusedMs;
		if (fetched.kind === "refused" && until > now) remember(refused, id, until, limits.entries);
		return undefined;
	};

	return {
		find: (id) => {
			const now = clock.now();
			const hit = kept.get(id);
			if (hit && hit.until > now) return Promise.resolve(hit.value);
			kept.delete(id);
			if ((refused.get(id) ?? 0) > now) return Promise.resolve(undefined);
			refused.delete(id);
			const joined = running.get(id);
			if (joined) return joined;
			// Past the limit there is no waiting: the id is none for now, and nothing is remembered.
			if (running.size >= limits.concurrent) return Promise.resolve(undefined);
			const job = load(id)
				.catch((): Fetched<T> => ({ kind: "failed" }))
				.then((fetched) => settle(id, fetched, now))
				.finally(() => running.delete(id));
			running.set(id, job);
			return job;
		},
	};
}
