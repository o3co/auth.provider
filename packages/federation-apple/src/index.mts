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

export type { AppleProvider, AppleProviderConfig } from "./apple.mjs";
export {
	APPLE_ISSUER,
	APPLE_PRIVATE_RELAY_DOMAIN,
	appleFederationModule,
	createAppleProvider,
	isPrivateRelayEmail,
} from "./apple.mjs";
export type { AppleClientSecretOptions } from "./client-secret.mjs";
export {
	APPLE_AUDIENCE,
	APPLE_CLIENT_SECRET_DEFAULT_LIFETIME_SECONDS,
	APPLE_CLIENT_SECRET_MAX_LIFETIME_SECONDS,
	APPLE_CLIENT_SECRET_RENEWAL_WINDOW_SECONDS,
	createAppleClientSecret,
} from "./client-secret.mjs";
