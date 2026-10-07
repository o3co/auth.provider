/**
 * The replay key of the write `writeId` to `key`, a key under `prefix`:
 * `<prefix>w:{<tag>}:<writeId>`, where `<tag>` is the part of `key` Redis
 * hashes, so it hashes as `key` does. `null` when no such key hashes as `key`
 * does: a key whose braces leave it no tag (a `}` with no `{` before it, or an
 * empty `{}`) is hashed whole, and `{<key>}` would end at its first `}`.
 */
export declare function replayKeyOf(key: string, prefix: string, writeId: string): string | null;
//# sourceMappingURL=replay-key.d.mts.map