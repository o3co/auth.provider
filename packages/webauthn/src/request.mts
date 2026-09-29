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
 * Express Request augmentation for the WebAuthn package.
 *
 * Upstream auth middleware that sets `req.webauthnSubject` should import
 * `WebAuthnSubject` from this package. Importing any export from
 * `@o3co/auth-provider-webauthn` also merges the `declare global` Express
 * Request augmentation into the consumer's TypeScript build. It uses the
 * global Express namespace, the stable augmentation target for Express v4 and
 * v5, as `req.oauthClient` does (`packages/oauth/src/middleware/clientAuth.mts`).
 */

/**
 * Authenticated subject required by WebAuthn registration endpoints, set by
 * upstream auth middleware (session cookie or Bearer token) before any
 * registration route is reached. Absent when the request has not been
 * authenticated.
 *
 * `userId` MUST be opaque and MUST NOT contain PII (email, username, etc.)
 * per WebAuthn §5.4.3: it is the user handle presented to the authenticator,
 * and may be persisted and synced by the device.
 */
export interface WebAuthnSubject {
	readonly userId: string;
	readonly userName?: string;
	readonly userDisplayName?: string;
}

declare global {
	namespace Express {
		interface Request {
			/**
			 * The authenticated WebAuthn subject, set by upstream session / bearer
			 * middleware. Absent when the request has not been authenticated.
			 */
			webauthnSubject?: WebAuthnSubject;
		}
	}
}
