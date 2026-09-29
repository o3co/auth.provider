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

// @o3co/auth-provider-webauthn
export { type WebAuthnConfig, webauthnConfigSchema } from "./config.mjs";
export { WEBAUTHN_GRANT_TYPE } from "./grant.mjs";
export { WEBAUTHN_ALGORITHM_IDS } from "./internal/options.mjs";
export { webauthnModule } from "./module.mjs";
// WebAuthnSubject + Express Request augmentation — consumers importing this
// package gain the augmentation automatically via declaration merging.
export type { WebAuthnSubject } from "./request.mjs";
// The rate-limit key for POST /oauth/webauthn/authentication/options.
// Operator-facing: it is what a `limits` entry on a RateLimiter adapter is
// keyed by when overriding the per-endpoint spec.
export { WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG } from "./routes/authenticationOptions.mjs";
// The session-admission ADR's D8: the bridge from the admitted browser session
// to `req.webauthnSubject`, as a module the deployment installs.
export {
	WEBAUTHN_SESSION_SUBJECT_ROUTE_ID,
	type WebAuthnSessionSubjectOptions,
	webauthnSessionSubjectModule,
} from "./sessionSubject.mjs";
