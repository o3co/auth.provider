/**
 * The command plumbing the ioredis clients share: a script run EVALSHA-first, falling back to
 * EVAL on `NOSCRIPT` alone, and the check that no command queued in a MULTI/EXEC failed unseen.
 */
import type { Redis } from "ioredis";
import type { CachedScript } from "./scripts/define.mjs";
/**
 * Whether `err` is Redis's `NOSCRIPT`, the cold-cache reply to `EVALSHA` after a `SCRIPT FLUSH`
 * or a failover: the signal to fall back to `EVAL` (which reloads the script), not to fail. It
 * reads the message because ioredis's `ReplyError` carries no code (ioredis's own `Script` does
 * the same); the text decides this boolean only and is never logged or thrown.
 */
export declare function isNoScriptError(err: unknown): boolean;
/**
 * Run `script` EVALSHA-first, falling back to EVAL — which implicitly loads
 * it server-side — on `NOSCRIPT`. Any other error is the caller's.
 */
export declare function runScript(io: Redis, script: CachedScript, keys: readonly string[], args: readonly string[]): Promise<unknown>;
/**
 * Surfaces per-command failures from a `MULTI`/`EXEC` reply. ioredis resolves `exec()` with one
 * `[error, result]` per queued command and does not reject when one failed, so a refused
 * `PEXPIRE … NX/GT` would leave a key with no TTL while the caller is told the write worked.
 *
 * `null`, the WATCH abort, passes through: the refresh-token family's CAS loop retries on it.
 * The first failure throws, naming the operation in fixed words with the reply's error as
 * `cause`, never in the message: Redis's reply can quote the command's arguments.
 * `loggableError` projects the cause for the operator without them.
 */
export declare function assertPipelineSucceeded(reply: unknown[] | null, operation: string): unknown[] | null;
//# sourceMappingURL=commands.d.mts.map