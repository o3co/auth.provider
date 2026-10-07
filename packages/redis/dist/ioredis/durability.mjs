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
 * A reply that refuses the question — an unknown or renamed command, an
 * unknown subcommand, `NOPERM`, a command a managed service disabled — rather
 * than one that says the server cannot answer now (`BUSY`, `LOADING`,
 * `NOAUTH`, `READONLY`, anything else), which fails the boot as any store
 * outage at boot does.
 */
const REFUSED_QUESTION = /^(?:NOPERM\b|ERR unknown command\b|ERR unknown subcommand\b|ERR\b.*\b(?:disabled|not allowed|not permitted|not supported|not available)\b)/i;
const isRefusal = (err) => err instanceof Error && err.name === "ReplyError" && REFUSED_QUESTION.test(err.message);
/**
 * `CONFIG GET <name>`'s value: the reply is `[name, value]`, or empty for a name the server
 * does not know.
 */
const configValue = (reply, name) => Array.isArray(reply) && reply[0] === name && typeof reply[1] === "string" ? reply[1] : undefined;
/** An `INFO` section's `<name>:<value>` line's value. */
const infoValue = (section, name) => typeof section === "string"
    ? new RegExp(`^${name}:([^\\r\\n]*)`, "m").exec(section)?.[1]
    : undefined;
/**
 * A reply about the eviction policy that is neither a policy nor a refusal. The boot fails on
 * it: read as unread, it would let `assumeNoEviction` stand in for a policy the server may have
 * reported.
 */
const undocumentedPolicyReply = (question) => new Error(`redisDurability: ${question} answered a reply it does not document; the eviction policy is neither read nor unread`);
/** `CONFIG GET`'s entries: a flat `[name, value, …]` array (RESP2) or a map (RESP3); `undefined` for another shape. */
const configEntries = (reply) => {
    if (Array.isArray(reply)) {
        if (reply.length % 2 !== 0)
            return undefined;
        const entries = [];
        for (let i = 0; i < reply.length; i += 2)
            entries.push([reply[i], reply[i + 1]]);
        return entries;
    }
    if (reply instanceof Map)
        return [...reply.entries()];
    if (typeof reply === "object" && reply !== null) {
        const proto = Object.getPrototypeOf(reply);
        if (proto === Object.prototype || proto === null)
            return Object.entries(reply);
    }
    return undefined;
};
/**
 * `CONFIG GET maxmemory-policy`'s value, in either reply shape: `undefined` when the question
 * was refused or the server knows no such parameter (an empty reply); any other reply throws.
 */
const configPolicy = (reply) => {
    if (reply === undefined)
        return undefined;
    const entries = configEntries(reply);
    if (entries === undefined)
        throw undocumentedPolicyReply("CONFIG GET maxmemory-policy");
    if (entries.length === 0)
        return undefined;
    const [entry] = entries;
    if (entries.length !== 1 || entry?.[0] !== "maxmemory-policy" || typeof entry[1] !== "string") {
        throw undocumentedPolicyReply("CONFIG GET maxmemory-policy");
    }
    return entry[1];
};
/**
 * `INFO memory`'s `maxmemory_policy`, judged on every line that names it: `undefined` when the
 * question was refused or no line names it; a reply that is no text, or names it with
 * different values, throws.
 */
const infoPolicy = (section) => {
    if (section === undefined)
        return undefined;
    if (typeof section !== "string")
        throw undocumentedPolicyReply("INFO memory");
    const values = new Set(Array.from(section.matchAll(/^maxmemory_policy:([^\r\n]*)/gm), (match) => match[1] ?? ""));
    if (values.size > 1)
        throw undocumentedPolicyReply("INFO memory");
    return values.values().next().value;
};
/**
 * What `io`'s server says about keeping what it is written. The policy from `INFO memory`
 * (`CONFIG GET maxmemory-policy` only where INFO does not say, so a managed server that blocks
 * `CONFIG` still reports it); AOF from `INFO persistence`; `CONFIG GET save` only when AOF is
 * off, to tell RDB snapshots from none. A refused question leaves its part unread; a policy
 * reply it cannot read either way (another shape, or INFO naming the policy twice, differently)
 * throws, as any other failure does, and is the caller's. `assumeNoEviction` is reported only
 * when set.
 */
export async function redisDurability(io, options = {}) {
    let refusal;
    const ask = async (question) => {
        try {
            return await question();
        }
        catch (err) {
            if (!isRefusal(err))
                throw err;
            refusal ??= err;
            return undefined;
        }
    };
    const maxmemoryPolicy = infoPolicy(await ask(() => io.info("memory"))) ??
        configPolicy(await ask(() => io.config("GET", "maxmemory-policy")));
    const aof = infoValue(await ask(() => io.info("persistence")), "aof_enabled");
    const appendOnly = aof === "1" ? true : aof === "0" ? false : undefined;
    let snapshots;
    if (appendOnly === false) {
        const save = configValue(await ask(() => io.config("GET", "save")), "save");
        snapshots = save === undefined ? undefined : save.trim() !== "";
    }
    return {
        maxmemoryPolicy,
        appendOnly,
        snapshots,
        refusal,
        ...(options.assumeNoEviction === true ? { assumeNoEviction: true } : {}),
    };
}
