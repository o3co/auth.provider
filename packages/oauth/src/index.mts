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

// #529: Client ID Metadata Documents — a client whose client_id is the https
// URL of its own registration (draft-ietf-oauth-client-id-metadata-document).
export {
	type ClientIdMetadataDocumentOptions,
	type ClientIdMetadataDocumentResolver,
	createClientIdMetadataDocumentResolver,
	isClientIdMetadataDocumentUrl,
	withClientIdMetadataDocuments,
} from "./clients/clientIdMetadataDocument.mjs";
export {
	type BroadcastBackchannelLogoutOptions,
	type BroadcastRP,
	broadcastBackchannelLogout,
} from "./logout/broadcastBackchannel.mjs";
export type {
	CascadeLogoutOptions,
	CascadeLogoutResult,
} from "./logout/cascadeLogout.mjs";
export { cascadeLogout } from "./logout/cascadeLogout.mjs";
export {
	type FrontchannelRP,
	type RenderFrontchannelLogoutHtmlOptions,
	renderFrontchannelLogoutHtml,
} from "./logout/renderFrontchannel.mjs";
// #484: private_key_jwt client authentication (RFC 7523 §2.2).
export type {
	ClientAssertionOutcome,
	ClientAssertionVerifier,
	ClientAssertionVerifierOptions,
} from "./middleware/clientAssertion.mjs";
export {
	CLIENT_ASSERTION_ALGORITHMS,
	createClientAssertionVerifier,
	JWT_BEARER_CLIENT_ASSERTION_TYPE,
	MAX_CLIENT_ASSERTION_LIFETIME_SECONDS,
} from "./middleware/clientAssertion.mjs";
export type { ClientAuthMiddlewareOptions } from "./middleware/clientAuth.mjs";
export { createClientAuthMiddleware } from "./middleware/clientAuth.mjs";
export { oauthModule } from "./module.mjs";
export { oauthAuthorizationModule } from "./oauthAuthorization.mjs";
export { oauthSessionModule } from "./oauthSession.mjs";
export { createOAuthRouter } from "./routes.mjs";
export {
	extractConfirmation,
	type IntrospectResponse,
	isCompoundConfirmation,
} from "./types/introspect.mjs";
