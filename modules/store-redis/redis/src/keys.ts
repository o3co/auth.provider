import type { Key, Space } from "@mod/store";

const enc = encodeURIComponent;
/** A text matched literally by SCAN's pattern. */
export const literal = (text: string) => text.replace(/[*?[\]\\]/g, (c) => `\\${c}`);

/** The Redis keys of the store's entries under `prefix`: each partition's keys share one hash slot. */
export function keysUnder(prefix: string) {
	const slot = (key: Key) => `${prefix}:{${enc(key.space.name)}:${enc(key.partition)}}`;
	return {
		slot,
		valueKey: (key: Key) => `${slot(key)}:v:${enc(key.name)}`,
		counterKey: (key: Key) => `${slot(key)}:c:${enc(key.name)}`,
		versionKey: (key: Key) => `${slot(key)}:#version`,
		markKey: (key: Key, mark: string | undefined) => `${slot(key)}:#mark:${enc(mark ?? "")}`,
		/** The control record and the ledger of spaces: outside every space, whose names hold no `#`. */
		controlKey: `${prefix}:{#control}`,
		ledgerKey: `${prefix}:{#ledger}`,
		/** SCAN's pattern for the space's value keys alone. */
		spaceValues: (space: Space) => `${literal(`${prefix}:{${enc(space.name)}:`)}*}:v:*`,
		/** The key of the space a value key SCAN found names. */
		keyAt: (space: Space, at: string): Key => {
			const head = `${prefix}:{${enc(space.name)}:`;
			const [partition = "", name = ""] = at.slice(head.length).split("}:v:");
			return { space, partition: decodeURIComponent(partition), name: decodeURIComponent(name) };
		},
	};
}
