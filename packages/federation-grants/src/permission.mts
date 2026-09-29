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
 * `allowedFederationGrantConnections`, read defensively (the federation-grants
 * ADR, D9).
 *
 * `ClientRepository` is a port, and a deployment's own repository validates
 * nothing this package can see. One that answers a comma-joined string would
 * turn the permission check into a substring match, where
 * `"calendar,mail".includes("cal")` is `true`. So anything that is not an
 * array reads as an empty allowlist — what absence means: nothing is allowed
 * — and an array keeps only its strings. The reader is core's
 * `federationGrantAllowlist`, shared with lodging and the consent page.
 */

import { federationGrantAllowlist } from "@o3co/auth-provider-core";
import type { Request } from "express";

export function allowedConnectionsOf(req: Request): readonly string[] {
	return federationGrantAllowlist(
		(
			req as unknown as {
				oauthClient?: { allowedFederationGrantConnections?: unknown };
			}
		).oauthClient?.allowedFederationGrantConnections,
	);
}

export const allows = (req: Request, connection: string): boolean =>
	allowedConnectionsOf(req).includes(connection);
