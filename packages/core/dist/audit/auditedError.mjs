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
 * What an audit event may carry of an error.
 *
 * An audit sink is a record other systems read — a SIEM, a dashboard, a
 * compliance archive — and a deployment chooses it. A store's or an IdP's
 * error message is peer-written text: the arguments a Redis reply quotes
 * (a token among them), the input a JSON parser choked on, an upstream's own
 * description. `loggableError` decides what a log line may keep of that; an
 * audit event keeps less, because it is kept longer and read by more.
 */
import { auditErrorText } from "../errors/envelope.mjs";
import { loggableError } from "../logging/loggableError.mjs";
/**
 * The {@link AuditedError} of `err`, for an audit event's `details.cause`:
 * what kind of error it was and what caused it, bounded, and nothing a peer
 * wrote into either.
 */
export function auditedError(err) {
    const projected = loggableError(err);
    return {
        ...nameAndCode(projected),
        ...(projected.cause !== undefined ? { cause: nameAndCode(projected.cause) } : {}),
    };
}
function nameAndCode({ name, code }) {
    return {
        name: auditErrorText(name),
        ...(code !== undefined ? { code: auditErrorText(String(code)) } : {}),
    };
}
