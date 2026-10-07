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
 * The conditional-write convention: a generation a store issues for what it
 * guards, a value read with its generation, and the answers of a write applied
 * only at the generation the caller read. The rules every store keeps are
 * stated once, in docs/adapter-surface.md, "Conditional writes".
 */
import { randomUUID } from "node:crypto";
const GENERATION_SHAPE = /^[\x21\x23-\x7e]{1,128}$/;
/**
 * Whether `value` is a generation a store may answer: 1 to 128 visible ASCII
 * characters (0x21–0x7e) other than `"`, so that `"<generation>"` is a strong
 * ETag. Never throws.
 */
export function isStoreGeneration(value) {
    return typeof value === "string" && GENERATION_SHAPE.test(value);
}
/** A fresh generation: a random (v4) UUID. One way for a store that makes its own. */
export function newStoreGeneration() {
    return randomUUID();
}
/**
 * The bundled stores' write-lifetime bound, 24 hours. A set reads absent only
 * once this has passed since its last membership write, and a
 * `createIf(…, null)` commits or fails within it of the read that answered
 * `null`. The bound is allocated: the adapter declares its write lifetime W
 * (issue to commit or failure), and the port's owning module issues a
 * conditional write only within (bound − W) of its read
 * (docs/adapter-surface.md, "Conditional writes", rule 6).
 */
export const BUNDLED_STORE_WRITE_LIFETIME_MS = 24 * 60 * 60 * 1000;
/*
 * Core's readers of what a store answered. Each property is read once, and a
 * fresh frozen object is returned. Anything outside the type (another outcome,
 * a malformed generation, a property read that throws, `undefined` where
 * `null` is meant) is a TypeError naming the field, never a value. The caller
 * treats that as the store's outage: never as a write that happened, and
 * never as one that did not. A RangeError stays reserved for a caller's own
 * input. The field readers below are shared with the other readers of a
 * conditional port's answers in core; the root entry does not export them.
 */
/** `answer[key]`, read once; a TypeError when `answer` is no object or the read throws. */
export const field = (answer, key, what) => {
    if (typeof answer !== "object" || answer === null)
        throw new TypeError(`${what}: not an object`);
    try {
        return answer[key];
    }
    catch {
        throw new TypeError(`${what}: ${key} could not be read`);
    }
};
/** `answer.generation`, read once and required to be a well-formed generation. */
export const generationOf = (answer, what) => {
    const generation = field(answer, "generation", what);
    if (!isStoreGeneration(generation))
        throw new TypeError(`${what}: generation is malformed`);
    return generation;
};
/** `answer.outcome`, read once and required to be one of `outcomes`. */
export const outcomeOf = (answer, outcomes, what) => {
    const outcome = field(answer, "outcome", what);
    if (!outcomes.includes(outcome)) {
        throw new TypeError(`${what}: outcome is not one of ${outcomes.join(", ")}`);
    }
    return outcome;
};
/** Whether `answer` names `key`, its prototype chain included; a TypeError when that cannot be told. */
const names = (answer, key, what) => {
    try {
        return key in answer;
    }
    catch {
        throw new TypeError(`${what}: ${key} could not be read`);
    }
};
/** A versioned read: `null` when the store holds no live record, else the value and its generation. */
export function readVersioned(answer) {
    if (answer === null)
        return null;
    const what = "versioned read";
    const value = field(answer, "value", what);
    if (value === undefined && !names(answer, "value", what)) {
        throw new TypeError(`${what}: value is absent`);
    }
    const generation = generationOf(answer, what);
    return Object.freeze({ value, generation });
}
/**
 * `items` copied by one read of its length and one read of each index, so
 * neither an iterator nor a changing length decides what is copied.
 */
export const copyItems = (items, what) => {
    try {
        const length = items.length;
        if (!Number.isSafeInteger(length) || length < 0)
            throw new TypeError("length");
        const copy = [];
        for (let i = 0; i < length; i += 1)
            copy.push(items[i]);
        return copy;
    }
    catch {
        throw new TypeError(`${what}: items could not be read`);
    }
};
/**
 * A versioned set read: the items copied into a new frozen array, each item
 * the port's to judge. A `null` generation is an absent set's, so it holds
 * no items.
 */
export function readVersionedSet(answer) {
    const what = "versioned set read";
    const items = field(answer, "items", what);
    if (!Array.isArray(items))
        throw new TypeError(`${what}: items is not an array`);
    const copy = copyItems(items, what);
    const generation = field(answer, "generation", what);
    if (generation === null) {
        if (copy.length > 0)
            throw new TypeError(`${what}: items held by an absent set`);
    }
    else if (!isStoreGeneration(generation)) {
        throw new TypeError(`${what}: generation is malformed`);
    }
    return Object.freeze({ items: Object.freeze(copy), generation });
}
/** A conditional replace's answer. */
export function readConditionalReplaceAnswer(answer) {
    const what = "conditional replace answer";
    const outcome = outcomeOf(answer, ["updated", "missing", "conflict"], what);
    if (outcome !== "updated")
        return Object.freeze({ outcome });
    return Object.freeze({ outcome, generation: generationOf(answer, what) });
}
/** A record-scoped conditional remove's answer: the outcome alone. */
export function readConditionalRemoveAnswer(answer) {
    const outcome = outcomeOf(answer, ["removed", "missing", "conflict"], "conditional remove answer");
    return Object.freeze({ outcome });
}
/** A conditional create's answer. */
export function readConditionalCreateAnswer(answer) {
    const what = "conditional create answer";
    const outcome = outcomeOf(answer, ["created", "conflict"], what);
    if (outcome !== "created")
        return Object.freeze({ outcome });
    return Object.freeze({ outcome, generation: generationOf(answer, what) });
}
/** A set-scoped conditional remove's answer: `removed` always with the set's new generation. */
export function readConditionalSetRemoveAnswer(answer) {
    const what = "conditional set remove answer";
    const outcome = outcomeOf(answer, ["removed", "missing", "conflict"], what);
    if (outcome !== "removed")
        return Object.freeze({ outcome });
    return Object.freeze({ outcome, generation: generationOf(answer, what) });
}
