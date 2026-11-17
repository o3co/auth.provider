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
 * Why the passkey store's ports cannot be used, or none, the one statement of them: exactly one of
 * `updateAsOne` and `updateTogether`, to change both spaces as one; each space's `erase` and
 * `migrate` all four, or none.
 */
export function portsRefused(store: PasskeyStore): string | undefined {
	const asOne = [store.updateAsOne, store.updateTogether].filter((f) => typeof f === "function");
	if (asOne.length !== 1) {
		return "its passkey store offers exactly one of updateAsOne and updateTogether, to change both its spaces as one";
	}
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

type Together = NonNullable<PasskeyStore["updateTogether"]>;

/** The subject a record is written for: the one a passkey's record names, a holder's own. */
function subjectOf(place: keyof PasskeyKeys, value: StoredPasskey) {
	const subject = place === "credentials" ? keptOf(value).subject : holderOf(value).subject;
	if (subject === undefined) throw broken();
	return subject;
}

/**
 * The store's change of both spaces as one, as the writes that change a list ask it: `updateAsOne`
 * where the store offers it, each next a record is given an op, `create` where none is held, else
 * `move` to the subject it is written for (a change where it is that subject's already); a refusal
 * is unavailable. `updateTogether` where offered instead. TODO(0.20, the remove step): `updateAsOne` only.
 */
export function togetherOf(store: PasskeyStore): Together {
	const { updateAsOne, updateTogether } = store;
	if (updateTogether) return updateTogether.bind(store);
	if (!updateAsOne) throw broken();
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
		const answer = await updateAsOne.call(store, {
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
