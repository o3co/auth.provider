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
import { describeValue } from "../errors/describe-value.mjs";
const INSTALL = "Install the session module's guard (sessionModule), or one that keeps core's CsrfGuard contract.";
const refuse = (member, rule) => {
    throw new RangeError(`csrfGuard.${member} ${rule}. ${INSTALL}`);
};
/** A member of the guard, read once; a read that throws is refused, naming the member. */
const readOnce = (member, read) => {
    try {
        return read();
    }
    catch (cause) {
        throw new RangeError(`csrfGuard.${member} could not be read. ${INSTALL}`, { cause });
    }
};
/**
 * `Reflect.apply` as core loaded: what the snapshot calls the guard's
 * functions through, so a function's own `bind`, `call` or `apply` — which
 * the guard's author controls — is never what runs.
 */
const reflectApply = Reflect.apply;
/** `fn` called on `guard` with the caller's arguments, through `reflectApply`. */
const onGuard = (fn, guard) => (...args) => reflectApply(fn, guard, args);
/** The disposers a guard may carry, which boot's dispose reaches through the snapshot. */
const DISPOSERS = [
    [Symbol.asyncDispose, "[Symbol.asyncDispose]"],
    [Symbol.dispose, "[Symbol.dispose]"],
];
/**
 * `value` as the slot holds it: a frozen snapshot of the guard, each member
 * read once. `middleware` must be a function of at most three parameters —
 * Express takes one of four or more for an error handler and skips it — and
 * `check` a function. The other members are carried as read.
 *
 * Every function of the snapshot is core's own, calling the guard's on the
 * guard it was read from through `reflectApply`: so a guard written as a
 * class answers as it would itself, nothing the guard carries decides what
 * is called, and `middleware` stays a request handler of three parameters
 * whatever later happens to the guard's function. A disposer the guard
 * carries (`Symbol.asyncDispose`, `Symbol.dispose`) is carried the same way,
 * so boot's dispose reaches the guard through the snapshot.
 *
 * @throws RangeError naming the member that breaks the contract or whose
 *   read throws (the read's error as its `cause`), or the slot when it holds
 *   no guard object.
 */
function snapshotOf(value) {
    if ((typeof value !== "object" && typeof value !== "function") || value === null) {
        throw new RangeError(`csrfGuard must be the guard object its contract describes, and the composition's slot holds ${describeValue(value)}. ${INSTALL}`);
    }
    const guard = value;
    const member = (key, name = String(key)) => readOnce(name, () => guard[key]);
    const method = (key, name = String(key)) => {
        const read = member(key, name);
        return typeof read === "function" ? Object.freeze(onGuard(read, guard)) : read;
    };
    const middleware = member("middleware");
    const arity = typeof middleware === "function" ? readOnce("middleware", () => middleware.length) : undefined;
    if (typeof middleware !== "function" || typeof arity !== "number" || arity > 3) {
        const held = typeof middleware !== "function"
            ? describeValue(middleware)
            : typeof arity === "number"
                ? `a function of ${arity} parameters`
                : `a function whose length is ${describeValue(arity)}`;
        return refuse("middleware", `is not a request handler: the routes it guards mount it in front of themselves, so it must be a function of at most three parameters, and the composition's slot holds ${held}`);
    }
    const check = method("check");
    if (typeof check !== "function") {
        refuse("check", `is not a function: the routes that answer a refusal in their own vocabulary ask it, and the composition's slot holds ${describeValue(check)}`);
    }
    const bodyField = member("bodyField");
    const snapshot = {
        cookieName: member("cookieName"),
        headerName: member("headerName"),
        ...(bodyField === undefined ? {} : { bodyField }),
        check,
        checkNavigation: method("checkNavigation"),
        middleware: Object.freeze((req, res, next) => reflectApply(middleware, guard, [req, res, next])),
        issue: method("issue"),
    };
    for (const [key, name] of DISPOSERS) {
        const disposer = method(key, name);
        if (typeof disposer === "function")
            snapshot[key] = disposer;
    }
    return Object.freeze(snapshot);
}
/**
 * Stage 3's handling of the `csrfGuard` slot in `components`, the working
 * map.
 *
 * - A host's value is replaced before any provider runs; one that breaks
 *   the contract is refused with the check's RangeError, naming the member.
 * - A provider's value is replaced as it is materialised; its refusal is the
 *   caller's to report, after its rollback, as a failed provider. A cleanup
 *   is still handed the provider's own value.
 * - An empty key stays empty, as `undefined` does: a slot left unfilled is
 *   stage 3's to judge against what requires it.
 */
export function csrfGuardSlotFor(components) {
    return {
        beforeProviders() {
            if (!Object.hasOwn(components, "csrfGuard") || components.csrfGuard === undefined)
                return;
            components.csrfGuard = snapshotOf(components.csrfGuard);
        },
        provided(key, value) {
            return key === "csrfGuard" && value !== undefined ? snapshotOf(value) : value;
        },
    };
}
