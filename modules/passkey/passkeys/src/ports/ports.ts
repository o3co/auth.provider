import { broken, holderOf, keptOf } from "../records/records.ts";
import type {
	PasskeyKey,
	PasskeyKeys,
	PasskeyOp,
	PasskeyStore,
	RegistrationChallengeStore,
	StoredPasskey,
} from "../store.ts";

/**
 * Why the passkey store's ports cannot be used, or none, the one statement of them: each space's
 * `erase` and `migrate` all four, or none.
 */
export function portsRefused(store: PasskeyStore): string | undefined {
	const { credentials: c, subjects: s } = store;
	const erasing = [c.erase, c.migrate, s.erase, s.migrate].filter((f) => f !== undefined);
	if (erasing.length % 4 !== 0) {
		return "its passkey store offers part of erase and migrate: both, in both spaces, or none";
	}
	return undefined;
}

/** Why the registration challenge store's ports cannot be used, or none: `erase` and `migrate` both, or neither. */
export function registrationPortsRefused(store: RegistrationChallengeStore): string | undefined {
	if ((store.erase === undefined) === (store.migrate === undefined)) return undefined;
	return "its registration challenge store offers one of erase and migrate: both, or neither";
}

/** What records of both spaces changed as one held, by space: the keys named, then the watched ones, in order. */
export interface PasskeysRead {
	readonly credentials: readonly (StoredPasskey | undefined)[];
	readonly subjects: readonly (StoredPasskey | undefined)[];
}

/** The next of each record read, by space in the order read; none keeps it. */
export interface PasskeysNext {
	readonly credentials?: readonly ({ readonly value: StoredPasskey } | undefined)[];
	readonly subjects?: readonly ({ readonly value: StoredPasskey } | undefined)[];
}

/** One record of a change as one: what it held, and holds after. */
export interface ChangedPasskey {
	readonly before: StoredPasskey | undefined;
	readonly after: StoredPasskey | undefined;
}

/**
 * A change of both spaces as one, in the words the writes that change a list use: the keys named
 * by space, and those `watch` names from what they hold; `change` answers the next of each, by
 * space in the order read, and runs again on a race; a record it leaves out is kept.
 */
type Together = (
	keys: PasskeyKeys,
	p: {
		readonly watch: (read: PasskeysRead) => Partial<PasskeyKeys>;
		readonly change: (read: PasskeysRead) => PasskeysNext;
	},
) => Promise<{
	readonly credentials: readonly ChangedPasskey[];
	readonly subjects: readonly ChangedPasskey[];
}>;

/** The subject a record is written for: the one a passkey's record names, a holder's own. */
function subjectOf(place: keyof PasskeyKeys, value: StoredPasskey) {
	const subject = place === "credentials" ? keptOf(value).subject : holderOf(value).subject;
	if (subject === undefined) throw broken();
	return subject;
}

/**
 * The store's change of both spaces as one, as the writes that change a list ask it, through
 * `updateAsOne`: each next a record is given an op, `create` where none is held, else `move` to the
 * subject it is written for (a change where it is that subject's already); a refusal is unavailable.
 */
export function togetherOf(store: PasskeyStore): Together {
	return async (keys, p) => {
		const named = (k: Partial<PasskeyKeys>): PasskeyKey[] => [
			...(k.credentials ?? []).map((key) => ({ place: "credentials" as const, key })),
			...(k.subjects ?? []).map((key) => ({ place: "subjects" as const, key })),
		];
		const bySpace = <V>(names: readonly PasskeyKey[], values: readonly V[]) => ({
			credentials: values.filter((_, n) => names[n]?.place === "credentials"),
			subjects: values.filter((_, n) => names[n]?.place === "subjects"),
		});
		const targets = named(keys);
		let watched: readonly PasskeyKey[] = [];
		const answer = await store.updateAsOne({
			targets,
			watch: (read) => {
				watched = named(
					p.watch(
						bySpace(
							targets,
							read.map((r) => r?.value),
						),
					),
				);
				return watched;
			},
			decide: (read, others) => {
				const names = [...targets, ...watched];
				const held = [...read, ...others];
				const next = p.change(
					bySpace(
						names,
						held.map((r) => r?.value),
					),
				);
				const ops = names.map(({ place }, n): PasskeyOp | undefined => {
					const nth = names.slice(0, n).filter((m) => m.place === place).length;
					const given = next[place]?.[nth];
					if (!given) return undefined;
					const subject = subjectOf(place, given.value);
					return held[n] === undefined
						? { kind: "create", value: given.value, lifetimeMs: "endless", subject }
						: { kind: "move", value: given.value, to: subject };
				});
				return { targets: ops.slice(0, targets.length), watched: ops.slice(targets.length) };
			},
		});
		if (answer.kind === "refused") throw broken();
		const changed = [...answer.targets, ...answer.watched].map((c) => ({
			before: c.before?.value,
			after: c.after?.value,
		}));
		return bySpace([...targets, ...watched], changed);
	};
}
