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

import type { Request } from "express";

/**
 * Read one cookie off a request, whether or not `cookie-parser` is mounted.
 *
 * `cookie-parser` is not a dependency of this package, but a composition root
 * is free to mount it; prefer its output when present and fall back to parsing
 * the raw header. Shared by the CSRF double-submit check and the federation
 * transaction cookie so the two cannot disagree about what "the cookie is
 * present" means.
 */
export const readCookie = (req: Request, name: string): string | undefined => {
	const parsed = (req as { cookies?: unknown }).cookies;
	if (parsed !== null && typeof parsed === "object") {
		const value = (parsed as Record<string, unknown>)[name];
		if (typeof value === "string" && value.length > 0) return value;
	}
	const header = req.headers?.cookie;
	if (typeof header !== "string") return undefined;
	for (const pair of header.split(";")) {
		const eq = pair.indexOf("=");
		if (eq === -1) continue;
		if (pair.slice(0, eq).trim() !== name) continue;
		const raw = pair.slice(eq + 1).trim();
		try {
			return decodeURIComponent(raw);
		} catch {
			// A cookie value that is not valid percent-encoding is not one we
			// issued. Hand back the raw text and let the caller's own check
			// reject it, rather than throwing out of a request guard.
			return raw;
		}
	}
	return undefined;
};
