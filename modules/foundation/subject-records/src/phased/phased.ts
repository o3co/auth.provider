import type { Elsewhere, SubjectReading, Walk } from "@mod/erasure-extensions";
import { type Clock, isUnavailable, Unavailable } from "@mod/kernel";
import type { Json } from "@mod/store";
import { eraseSubject } from "../erase/erase.ts";
import type { Phase, SubjectPlace } from "../index/index.ts";
import { migrateRecords } from "../migrate/migrate.ts";
import type { PhaseOnce } from "../phase/phase.ts";
import { subjectKeyedSetsIn } from "../sets/sets.ts";
import { subjectRecordsIn } from "../writes/writes.ts";

type Refuse = (where: string, reason: string) => never;
/** A builder's methods, each answering a promise. */
type Methods = Record<string, (...args: never[]) => Promise<unknown>>;

/** A refusal a builder finds once the start is over: it fails readiness, never a call. */
class Late extends Error {}

/**
 * A builder over the phase the process reads once, so a store's blip at start refuses no start: built
 * at once where the phase reads at build, refusing as the builder does; else at the first call
 * that reads it, each call unavailable until then. A refusal found then keeps `ready` failing, with
 * its reason, logged once, and every call unavailable. `ready` is the template's probe check.
 */
async function phased<B extends Methods>(
	phase: PhaseOnce,
	build: (phase: Phase, refuse: Refuse) => B,
	refuse: Refuse,
	place: Omit<SubjectPlace, "phase">,
	names: Readonly<Record<keyof B & string, true>>,
): Promise<B & { readonly ready: () => Promise<void> }> {
	let built: B | undefined;
	let refused: string | undefined;
	const late: Refuse = (where, reason) => {
		throw new Late(`${where}: ${reason}`);
	};
	try {
		built = build(await phase.read(), refuse);
	} catch (error) {
		if (!isUnavailable(error)) throw error;
	}
	const current = async (): Promise<B> => {
		if (built) return built;
		if (refused !== undefined) throw new Unavailable("subject-records");
		const read = await phase.read();
		try {
			built = build(read, late);
			return built;
		} catch (error) {
			if (!(error instanceof Late)) throw error;
			refused = error.message;
			place.log?.error("subject-records.refused", { space: place.space.name, reason: refused });
			throw new Unavailable("subject-records");
		}
	};
	const methods = Object.fromEntries(
		(Object.keys(names) as (keyof B & string)[]).map((name) => [
			name,
			async (...args: unknown[]) =>
				((await current())[name] as unknown as (...a: unknown[]) => Promise<unknown>)(...args),
		]),
	) as unknown as B;
	return {
		...methods,
		ready: async () => {
			if (refused !== undefined) throw new Error(refused);
			await current().catch((error: unknown) => {
				throw refused !== undefined ? new Error(refused) : error;
			});
		},
	};
}

/**
 * `subjectRecordsIn` over the phase the process reads once (see `phased`), with the space's
 * `erase` and `migrate` at that phase, as an owner's store ports take them: the wiring never
 * handles the phase.
 */
export const phasedRecordsIn = <T extends Json>(
	place: Omit<SubjectPlace, "phase">,
	phase: PhaseOnce,
	where: string,
	refuse: Refuse,
	options: { readonly secret?: true } = {},
) =>
	phased(
		phase,
		(read, told) => {
			const at = { ...place, phase: read };
			return {
				...subjectRecordsIn<T>(at, where, told, options),
				erase: (subject: string, signal: AbortSignal) => eraseSubject(at, subject, { signal }),
				migrate: (
					walk: Walk,
					subjectOf: SubjectReading,
					signal: AbortSignal,
					elsewhere?: Elsewhere,
				) => migrateRecords(at, walk, subjectOf, elsewhere ? { signal, elsewhere } : { signal }),
			};
		},
		refuse,
		place,
		// Every method the builder has, or the typecheck fails: none is left unrouted.
		{
			create: true,
			unowned: true,
			read: true,
			change: true,
			remove: true,
			move: true,
			scan: true,
			erase: true,
			migrate: true,
		} satisfies Record<keyof ReturnType<typeof subjectRecordsIn<T>> | "erase" | "migrate", true>,
	);

/** `subjectKeyedSetsIn` over the phase the process reads once (see `phased`). */
export const phasedKeyedSetsIn = (
	place: Omit<SubjectPlace, "phase"> & { readonly cap: number; readonly clock: Clock },
	phase: PhaseOnce,
	where: string,
	refuse: Refuse,
) =>
	phased(
		phase,
		(read, told) => subjectKeyedSetsIn({ ...place, phase: read }, where, told),
		refuse,
		place,
		{ add: true, members: true, remove: true, awaiting: true, settled: true } satisfies Record<
			keyof ReturnType<typeof subjectKeyedSetsIn>,
			true
		>,
	);
