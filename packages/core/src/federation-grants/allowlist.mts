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
 * A client's federation-grant registration list
 * (`allowedFederationGrantConnections`, `federationGrantRedirectUris`), read
 * defensively. An exported entry point that takes a client record from its
 * caller, such as lodging, cannot assume the record
 * came through the client-record boundary, and a comma-joined string would
 * turn membership into a substring match (`"calendar,mail".includes("cal")`),
 * allowing an ungranted connection or a prefix of a registered redirect URI.
 *
 * A non-array reads as an empty list (nothing allowed); an array keeps only
 * its strings. Every such entry point judges these fields through this reader.
 */
export function federationGrantAllowlist(value: unknown): readonly string[] {
	if (!Array.isArray(value)) return [];
	return value.filter((entry): entry is string => typeof entry === "string");
}
