import type { Elsewhere, SetReading, SubjectReading, Walk } from "@mod/erasure-extensions";
import { type Clock, isUnavailable, Unavailable } from "@mod/kernel";
import { changeRecords } from "@mod/records";
import type { Json } from "@mod/store";
import { eraseSubject } from "../erase/erase.ts";
import type { Phase, SubjectPlace } from "../index/index.ts";
import { jointRecordsIn } from "../joint/joint.ts";
import { migrateRecords, migrateSets } from "../migrate/migrate.ts";
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
	places: readonly Omit<SubjectPlace, "phase">[],
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
			for (const place of places) {
				place.log?.error("subject-records.refused", { space: place.space.name, reason: refused });
			}
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
export const phasedRecordsIn = async <T extends Json>(
	place: Omit<SubjectPlace, "phase">,
	phase: PhaseOnce,
	where: string,
	refuse: Refuse,
	options: { readonly secret?: true } = {},
) => ({
	...(await phased(
		phase,
		(read, told) => {
			const at = { ...place, phase: read };
			return {
				...subjectRecordsIn<T>(at, where, told, options),
				// A value removed is one this builder kept as T, or one kept raw under the subject's key.
				erase: (subject: string, signal: AbortSignal, eachRemoved?: (value: T) => void) =>
					eraseSubject(
						at,
						subject,
						eachRemoved
							? { signal, eachRemoved: eachRemoved as (value: Json) => void }
							: { signal },
					),
				migrate: (
					walk: Walk,
					subjectOf: SubjectReading,
					signal: AbortSignal,
					elsewhere?: Elsewhere,
				) => migrateRecords(at, walk, subjectOf, elsewhere ? { signal, elsewhere } : { signal }),
			};
		},
		refuse,
		[place],
		// Every method the builder has, or the typecheck fails: none is left unrouted.
		{
			create: true,
			unowned: true,
			read: true,
			change: true,
			changeNamed: true,
			remove: true,
			scan: true,
			erase: true,
			migrate: true,
		} satisfies Record<keyof ReturnType<typeof subjectRecordsIn<T>> | "erase" | "migrate", true>,
	)),
	/**
	 * The name a record keyed by a secret is kept by: records' own digest, read from the target the
	 * builder writes, so a record a 0.19 instance wrote under a secret is the one found. Needs no
	 * phase. Elsewhere a key is its own name.
	 */
	nameOf: (secret: string) =>
		options.secret ? changeRecords.keyOf({ place, secret }).partition : secret,
});

/** `subjectKeyedSetsIn` over the phase the process reads once (see `phased`). */
export const phasedKeyedSetsIn = (
	place: Omit<SubjectPlace, "phase"> & { readonly cap: number; readonly clock: Clock },
	phase: PhaseOnce,
	where: string,
	refuse: Refuse,
) =>
	phased(
		phase,
		(read, told) => {
			const at = { ...place, phase: read };
			return {
				...subjectKeyedSetsIn(at, where, told),
				erase: (subject: string, signal: AbortSignal) => eraseSubject(at, subject, { signal }),
				migrate: (walk: Walk, reading: SetReading, signal: AbortSignal) =>
					migrateSets(at, walk, reading, { signal }),
			};
		},
		refuse,
		[place],
		// Every method the builder has, or the typecheck fails: none is left unrouted.
		{
			add: true,
			members: true,
			remove: true,
			awaiting: true,
			settled: true,
			erase: true,
			migrate: true,
		} satisfies Record<keyof ReturnType<typeof subjectKeyedSetsIn> | "erase" | "migrate", true>,
	);

/**
 * `jointRecordsIn` over the phase the process reads once (see `phased`), sharing the template's one
 * read with its `phasedRecordsIn`: the joint change and the builders see one phase. It has no
 * `erase` or `migrate`: those are each place's builder's.
 */
export const phasedJointRecordsIn = <P extends string, T extends Json = Json>(
	places: Readonly<Record<P, Omit<SubjectPlace, "phase">>>,
	phase: PhaseOnce,
	where: string,
	refuse: Refuse,
) =>
	phased(
		phase,
		(read, told) => {
			const at = Object.fromEntries(
				(Object.entries(places) as [P, Omit<SubjectPlace, "phase">][]).map(([name, place]) => [
					name,
					{ ...place, phase: read },
				]),
			) as Record<P, SubjectPlace>;
			return jointRecordsIn<P, T>(at, where, told);
		},
		refuse,
		Object.values(places) as Omit<SubjectPlace, "phase">[],
		{ changeSubjectRecords: true } satisfies Record<keyof ReturnType<typeof jointRecordsIn>, true>,
	);
