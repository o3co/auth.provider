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
// ---------------------------------------------------------------------------
// BootError class — Per A2-β §6.1
// ---------------------------------------------------------------------------
/**
 * The single error class for the boot planner's scope. Every boot-time
 * failure surfaces as a BootError with a structured `details` payload and
 * a discriminated `reason` field.
 *
 * Codex Session 03 verdict: single class, discriminated reason, stage field.
 * `cause` is preserved verbatim for *-factory-failed reasons (verdict C3).
 *
 * Per A2-β §6.1.
 */
export class BootError extends Error {
    reason;
    stage;
    details;
    constructor(args) {
        // Pass `cause` to super only when defined. Calling
        // `super(message, { cause: undefined })` materialises an own `cause`
        // property with value `undefined`, breaking the spec §6.1 contract that
        // cause is populated only for *-factory-failed reasons.
        super(args.message, args.cause !== undefined ? { cause: args.cause } : undefined);
        this.name = "BootError";
        this.reason = args.reason;
        this.stage = args.stage;
        this.details = args.details;
    }
}
