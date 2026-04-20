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

export type { FederationProviderFactory } from "./federations/factory.mjs";
export { createFederationProviderFactory } from "./federations/factory.mjs";
export { createGoogleProvider } from "./federations/google.mjs";
export type {
	FederationProvider,
	FederationResult,
	VerifyUserContext,
} from "./federations/types.mjs";
export { sessionModule } from "./module.mjs";
export { createPassport } from "./passport.mjs";
export type { SessionStoreFactory } from "./store/factory.mjs";
export {
	createSessionStoreFactory,
	registerBuiltinSessionStores,
} from "./store/factory.mjs";
