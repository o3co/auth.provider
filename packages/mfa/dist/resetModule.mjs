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
 * `mfaResetModule`: the operator reset (`reset.mts`) as the `mfaReset`
 * component a Store reads after `createApp` returns
 * (`handle.components.mfaReset.resetMfaForSubject`).
 *
 * Installed beside `mfaModule`, apart from it: the reset ends every session
 * of the subject's, so it requires `subjectRevocationService` — a module of
 * its own — which the MFA routes do not. Requires the two MFA stores and
 * `mfaSubjectLeases`, the lease owner `mfaModule` builds from
 * `mfa.storeTimeoutMs` and every writer of a subject's factor set holds: so
 * the reset needs `mfaModule` installed, and where `mfa.mode = off` leaves it
 * out, the reset is unavailable — the boot refuses this module without it,
 * naming the slot. Reads `userRepository`, for the witness's clear alone
 * (`markMfaEnrolled`), `mailSender` (`requireEmailProof` needs one),
 * `auditSink` and `logger`, and no section. Eager, so its refusals are the
 * boot's.
 */
import { defineModule } from "@o3co/auth-provider-core";
import { createMfaReset } from "./reset.mjs";
const REQUIRES = [
    "mfaFactorStore",
    "mfaTransactionStore",
    "mfaSubjectLeases",
    "subjectRevocationService",
];
const OPTIONAL = ["userRepository", "mailSender", "auditSink", "logger"];
/** The operator reset's module (see this file's header). */
export const mfaResetModule = defineModule({
    name: "mfa-reset",
    requires: REQUIRES,
    optional: OPTIONAL,
    lifecycle: { mfaReset: { eager: true } },
    provides: {
        mfaReset: (deps) => createMfaReset({
            factorStore: deps.mfaFactorStore,
            transactionStore: deps.mfaTransactionStore,
            subjectRevocationService: deps.subjectRevocationService,
            leases: deps.mfaSubjectLeases,
            ...(deps.userRepository === undefined ? {} : { userRepository: deps.userRepository }),
            mailWired: deps.mailSender !== undefined,
            ...(deps.auditSink === undefined ? {} : { auditSink: deps.auditSink }),
            ...(deps.logger === undefined ? {} : { logger: deps.logger }),
        }),
    },
});
