import { createHash } from "node:crypto";

/**
 * How deferred work is spread: over this many records, so concurrent adds seldom meet, and how
 * much one record keeps. Each add or done rewrites its record whole, so a record stays small; a
 * full one refuses, and nothing already kept is ever pushed out. The wiring decides both.
 */
export interface DeferredSize {
	readonly shards: number;
	readonly perShard: number;
}

export const shardOf = (job: string, size: DeferredSize) =>
	createHash("sha256").update(job).digest().readUInt16BE(0) % size.shards;
