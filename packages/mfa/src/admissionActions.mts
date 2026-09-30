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

import type { AdmissionActionDeclaration } from "@o3co/auth-provider-core";

/**
 * The actions the MFA package's routes admit a browser session for, with the
 * grade each is registered under: `mfa.manage` — enrolling a factor outside a
 * login, removing one, regenerating recovery codes — changes the ways into
 * the account, so it is a `credential_change`.
 *
 * Declared, and registered by no module: a module registers only what its
 * own code admits, and the module whose route admits a session contributes
 * these as its `admissionActions`.
 */
export const MFA_ADMISSION_ACTIONS = Object.freeze({
	"mfa.manage": Object.freeze({ grade: "credential_change" }),
} as const satisfies Readonly<Record<string, AdmissionActionDeclaration>>);

/** An action the MFA package's routes admit. */
export type MfaAdmissionAction = keyof typeof MFA_ADMISSION_ACTIONS;
