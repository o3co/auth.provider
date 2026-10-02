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
 * The one reading of the `ClientRepository` an oauth entry point or grant is
 * handed (`createOAuthRouter`, `createClientAuthMiddleware`, the
 * authorization-code grant): behind core's client-record boundary, as the
 * outermost layer, so every registered client an endpoint reads is held to
 * the registration schema.
 */

import {
	type ClientRepository,
	type ClientRepositoryBoundaryOptions,
	validatedClientRepository,
} from "@o3co/auth-provider-core";
import { isClientIdMetadataDocumentFallback } from "./clientIdMetadataDocument.mjs";

/**
 * `repository` behind core's boundary (`validatedClientRepository`, which
 * answers a boundary as it is). A document fallback is answered as it is:
 * it reads its registered clients through the boundary already, and is
 * never wrapped, since a boundary over it would read its refusals as
 * absences and copy its document clients away from their provenance.
 */
export function behindClientBoundary(
	repository: ClientRepository,
	logger: NonNullable<ClientRepositoryBoundaryOptions["logger"]>,
): ClientRepository {
	if (isClientIdMetadataDocumentFallback(repository)) return repository;
	return validatedClientRepository(repository, { logger });
}
