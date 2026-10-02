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
 * The one reading of a `ClientRepository` an oauth entry point is handed:
 * behind core's client-record boundary, as the outermost layer, so a
 * composition that calls `createOAuthRouter` or `createClientAuthMiddleware`
 * itself reads validated client records.
 */

import {
	type ClientRepository,
	type ClientRepositoryBoundaryOptions,
	validatedClientRepository,
} from "@o3co/auth-provider-core";
import { isClientIdMetadataDocumentRepository } from "./clientIdMetadataDocument.mjs";

/**
 * `repository` behind core's boundary (`validatedClientRepository`): a no-op
 * for a repository that already is one. A document fallback
 * (`withClientIdMetadataDocuments`) is answered as it is: it reads its
 * registered clients through the boundary already, and its document clients
 * are its own, so wrapping it would copy them away from their provenance and
 * read its refusals as absences.
 */
export function behindClientBoundary(
	repository: ClientRepository,
	logger?: ClientRepositoryBoundaryOptions["logger"],
): ClientRepository {
	if (isClientIdMetadataDocumentRepository(repository)) return repository;
	return validatedClientRepository(repository, logger === undefined ? {} : { logger });
}
