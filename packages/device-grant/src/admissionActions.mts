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
 * The actions device verification admits, one per body action, with the grade
 * the device grant registers for each: a lookup and a denial grant nothing, so
 * a user refuses a phished device request without a step-up; an approval grants
 * a device a token.
 */
export const DEVICE_GRANT_ADMISSION_ACTIONS = Object.freeze({
	"device.lookup": Object.freeze({ grade: "grants_nothing" }),
	"device.approve": Object.freeze({ grade: "use" }),
	"device.deny": Object.freeze({ grade: "grants_nothing" }),
} as const satisfies Readonly<Record<string, AdmissionActionDeclaration>>);

/** An action device verification admits. */
export type DeviceGrantAdmissionAction = keyof typeof DEVICE_GRANT_ADMISSION_ACTIONS;
