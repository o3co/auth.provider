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
 * The actions this package admits, grouped by the module that registers them,
 * each exercising the session (`use`). `createOAuthRouter` admits the first
 * group; each session-bound grant admits its own.
 */

/** What `createOAuthRouter` admits: `/authorize` and the consent step. */
export const OAUTH_ROUTER_ADMISSION_ACTIONS = Object.freeze({
	"oauth.authorize": Object.freeze({ grade: "use" }),
	"oauth.consent": Object.freeze({ grade: "use" }),
} as const satisfies Readonly<Record<string, AdmissionActionDeclaration>>);

/** What the `session` grant admits. */
export const SESSION_GRANT_ADMISSION_ACTIONS = Object.freeze({
	"oauth.session_grant": Object.freeze({ grade: "use" }),
} as const satisfies Readonly<Record<string, AdmissionActionDeclaration>>);

/** What the `authorization_code` grant admits, at both of its reads. */
export const AUTHORIZATION_CODE_GRANT_ADMISSION_ACTIONS = Object.freeze({
	"oauth.code_exchange": Object.freeze({ grade: "use" }),
} as const satisfies Readonly<Record<string, AdmissionActionDeclaration>>);

/** What the `refresh_token` grant admits. */
export const REFRESH_TOKEN_GRANT_ADMISSION_ACTIONS = Object.freeze({
	"oauth.refresh": Object.freeze({ grade: "use" }),
} as const satisfies Readonly<Record<string, AdmissionActionDeclaration>>);
