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
 * `mfaRecoveryCodeFactorModule`: the recovery-code factor's module (the MFA
 * ADR's D1, D25), named after its section, `mfa-recovery-code-factor`, which
 * boot parses with the module's schema before any factory runs. It
 * contributes the factor as `mfaFactors.recovery_code`, issuing sets of
 * `count` codes. `enabled` is the module's switch (`section.isEnabled`):
 * false, and the module registers nothing. Stateless.
 */
import { defineModule } from "@o3co/auth-provider-core";
import { mfaRecoveryCodeFactorConfigSchema } from "./config.mjs";
import { createRecoveryCodeFactor, RECOVERY_CODE_FACTOR_KIND } from "./factor.mjs";
/** The recovery-code factor's module: its section, and the factor built from it. */
export const mfaRecoveryCodeFactorModule = defineModule({
    name: "mfa-recovery-code-factor",
    section: {
        schema: mfaRecoveryCodeFactorConfigSchema,
        reference: new URL("../../config/reference.conf", import.meta.url),
        isEnabled: (section) => section.enabled,
    },
    contributes: {
        mfaFactors: {
            [RECOVERY_CODE_FACTOR_KIND]: ({ section }) => createRecoveryCodeFactor({ count: section.count }),
        },
    },
});
