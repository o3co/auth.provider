import type { Key, Space } from "@mod/store";

const enc = encodeURIComponent;

/** The Redis keys of the store's entries under `prefix`: each partition's keys share one hash slot. */
export function keysUnder(prefix: string) {
	const slot = (key: Key) => `${prefix}:{${enc(key.space.name)}:${enc(key.partition)}}`;
	return {
		slot,
		valueKey: (key: Key) => `${slot(key)}:v:${enc(key.name)}`,
		counterKey: (key: Key) => `${slot(key)}:c:${enc(key.name)}`,
		versionKey: (key: Key) => `${slot(key)}:#version`,
		markKey: (key: Key, mark: string | undefined) => `${slot(key)}:#mark:${enc(mark ?? "")}`,
		/** What every slot of the space's partitions starts with, as SCAN matches it. */
		spaceHead: (space: Space) => `${prefix}:{${enc(space.name)}:`,
	};
}
