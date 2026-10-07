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
 * What an interruption may answer the browser: a `403` whose body holds only
 * the closed keys, an RFC 6749 error code, and the hints its requirement
 * declared, each in core's bounded grammar. Anything else is the
 * requirement's fault, a `RangeError`.
 */
import { isWellFormedErrorCode } from "../errors/envelope.mjs";
import { isObject } from "./input-values.mjs";
import { isHintKey, isHintToken } from "./requirement.mjs";
/** The keys an interruption's body may carry: closed, so a `user` snapshot, a `sub` or a `sid` cannot leave through it. */
const ANSWER_KEYS = new Set(["error", "transaction", "expires_in", "hints"]);
const BASE64URL = /^[A-Za-z0-9_-]+$/;
/** The hint grammar's caps: an integer's range, a list's length, a transaction's length. */
const HINT_NUMBER_MAX = 86_400;
const HINT_LIST_MAX = 16;
const TRANSACTION_MAX_LENGTH = 128;
/**
 * Holds an interruption's answer to the closed body (`ANSWER_KEYS`, `error`
 * in the RFC 6749 error-text class) and to the `hintKeys` the requirement
 * named `name` declared, each hint a boolean, a bounded integer or
 * enum-like tokens, so a snapshot, a URL, an address or a name cannot pass.
 * Answers a frozen copy; a body that fails is the requirement's fault, a
 * `RangeError` the route answers as an `open` failure.
 */
export function checkInterruptionAnswer(value, name, hintKeys) {
    const refuse = (what) => {
        throw new RangeError(`requirement "${name}" answered an interruption ${what}`);
    };
    if (!isObject(value))
        return refuse("that is not an object");
    if (value.status !== 403)
        refuse("whose status is not 403");
    // The body is read once into a null-prototype object, which is what gets
    // validated and answered: an own "__proto__" key is then an ordinary key,
    // not the prototype's setter.
    const bodyRead = value.body;
    if (!isObject(bodyRead) || Array.isArray(bodyRead))
        return refuse("without a body");
    const body = Object.create(null);
    for (const key of Object.keys(bodyRead))
        body[key] = bodyRead[key];
    for (const key of Object.keys(body)) {
        if (!ANSWER_KEYS.has(key)) {
            refuse(`whose body carries "${key}", which the body's shape does not admit`);
        }
    }
    const error = body.error;
    if (!isWellFormedErrorCode(error))
        refuse("whose error is not a well-formed error code");
    const transaction = body.transaction;
    if (transaction !== undefined) {
        if (typeof transaction !== "string" ||
            transaction.length > TRANSACTION_MAX_LENGTH ||
            !BASE64URL.test(transaction)) {
            refuse(`whose transaction is not a base64url string of at most ${TRANSACTION_MAX_LENGTH}`);
        }
    }
    const expiresIn = body.expires_in;
    if (expiresIn !== undefined) {
        if (!Number.isSafeInteger(expiresIn) || expiresIn <= 0) {
            refuse("whose expires_in is not a positive integer");
        }
    }
    let hints;
    const hintsRead = body.hints;
    if (hintsRead !== undefined) {
        if (!isObject(hintsRead) || Array.isArray(hintsRead)) {
            return refuse("whose hints are not an object");
        }
        hints = {};
        for (const key of Object.keys(hintsRead)) {
            const hint = hintsRead[key];
            if (!hintKeys.includes(key) || !isHintKey(key)) {
                refuse(`with a hint "${key}" it did not declare, or that is not a hint name`);
            }
            if (typeof hint === "boolean") {
                hints[key] = hint;
            }
            else if (typeof hint === "number") {
                if (!Number.isSafeInteger(hint) || hint < 0 || hint > HINT_NUMBER_MAX) {
                    refuse(`with a hint "${key}" that is not an integer in [0, ${HINT_NUMBER_MAX}]`);
                }
                hints[key] = hint;
            }
            else if (isHintToken(hint)) {
                hints[key] = hint;
            }
            else if (Array.isArray(hint) && hint.every(isHintToken)) {
                if (hint.length > HINT_LIST_MAX) {
                    refuse(`with a hint "${key}" that lists more than ${HINT_LIST_MAX} tokens`);
                }
                hints[key] = Object.freeze([...hint]);
            }
            else {
                refuse(`with a hint "${key}" that is not a boolean, an integer, or an enum-like token`);
            }
        }
    }
    return Object.freeze({
        status: 403,
        body: Object.freeze({
            error: error,
            ...(transaction === undefined ? {} : { transaction: transaction }),
            ...(expiresIn === undefined ? {} : { expires_in: expiresIn }),
            ...(hints === undefined ? {} : { hints: Object.freeze(hints) }),
        }),
    });
}
