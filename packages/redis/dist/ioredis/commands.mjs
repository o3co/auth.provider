/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * Whether `err` is Redis's `NOSCRIPT`, the cold-cache reply to `EVALSHA` after a `SCRIPT FLUSH`
 * or a failover: the signal to fall back to `EVAL` (which reloads the script), not to fail. It
 * reads the message because ioredis's `ReplyError` carries no code (ioredis's own `Script` does
 * the same); the text decides this boolean only and is never logged or thrown.
 */
export function isNoScriptError(err) {
    return err instanceof Error && err.message.includes("NOSCRIPT");
}
/**
 * Run `script` EVALSHA-first, falling back to EVAL — which implicitly loads
 * it server-side — on `NOSCRIPT`. Any other error is the caller's.
 */
export async function runScript(io, script, keys, args) {
    if (script.cached) {
        try {
            return await io.evalsha(script.sha, keys.length, ...keys, ...args);
        }
        catch (err) {
            if (!isNoScriptError(err))
                throw err;
            script.cached = false;
        }
    }
    const reply = await io.eval(script.source, keys.length, ...keys, ...args);
    script.cached = true;
    return reply;
}
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
export function assertPipelineSucceeded(reply, operation) {
    if (reply === null)
        return null;
    for (const entry of reply) {
        // ioredis tuple shape; a wrapper returning bare results simply has no
        // error slot to find, which is correct rather than silently lenient.
        const err = Array.isArray(entry) ? entry[0] : null;
        if (err) {
            throw new Error(`${operation}: a queued command failed inside MULTI/EXEC`, { cause: err });
        }
    }
    return reply;
}
