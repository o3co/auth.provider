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
 * The JSON body parser of the package's ceremony routes, and the body reading
 * of the session admission in front of the registration routes, with the one
 * limit they share: 100kb, where a real WebAuthn payload is under 10KB. A
 * parser that finds the body already read leaves it as it is, so the routes
 * behind the admission do not read it twice. Internal to the package.
 */

import express, { type RequestHandler } from "express";

/** The one content type the parser reads. */
const JSON_TYPE = "application/json";

/** The largest body the package reads. */
const LIMIT = "100kb";

/** A parser of a JSON request body within the package's limit. */
export const jsonBody = (): RequestHandler => express.json({ type: JSON_TYPE, limit: LIMIT });

/**
 * What remains of a body the JSON parser did not read, read to its end within
 * the same limit, whatever its framing and content type.
 */
const remainingBody = (): RequestHandler => express.raw({ type: () => true, limit: LIMIT });

/**
 * Refuses with `400 invalid_request` a body the JSON parser did not read that
 * has bytes; an empty one is left as the JSON parser leaves a body it does
 * not read.
 */
const refuseBytesNotJson: RequestHandler = (req, res, next) => {
	const body: unknown = req.body;
	if (Buffer.isBuffer(body)) {
		if (body.length > 0) {
			res.status(400).json({
				error: "invalid_request",
				error_description: "The request body must be application/json",
			});
			return;
		}
		req.body = undefined;
	}
	next();
};

/**
 * The body as the admission in front of the registration routes reads it:
 * to its end, whatever its framing, before anything after runs. A JSON body
 * is parsed as the routes parse it; any other body is read within the same
 * limit and refused with `400 invalid_request` when it has bytes, since the
 * routes would not read it. A request with no body, or an empty one, passes.
 */
export const wholeBody = (): RequestHandler[] => [jsonBody(), remainingBody(), refuseBytesNotJson];
