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
 * The JSON body parser of the package's ceremony routes, and of the session
 * admission in front of the registration routes, with the one limit they
 * share: 100kb, where a real WebAuthn payload is under 10KB. A parser that
 * finds the body already read leaves it as it is, so the routes behind the
 * admission do not read it twice. Beside it, the admission's refusal of a
 * body the parser would not read. Internal to the package.
 */

import express, { type RequestHandler } from "express";

/** The one content type the parser reads. */
const JSON_TYPE = "application/json";

/** A parser of a JSON request body within the package's limit. */
export const jsonBody = (): RequestHandler => express.json({ type: JSON_TYPE, limit: "100kb" });

/**
 * Refuses with `400 invalid_request` a request carrying a body that is not
 * JSON — one the parser leaves unread, so nothing in front of the parser
 * would wait for it to arrive, and its limit would not apply. A request with
 * no body, or an empty one (`Content-Length: 0`), passes.
 */
export const refuseBodyNotJson: RequestHandler = (req, res, next) => {
	const length = req.headers["content-length"];
	const carriesBody =
		req.headers["transfer-encoding"] !== undefined || (length !== undefined && length !== "0");
	if (carriesBody && !req.is(JSON_TYPE)) {
		res.status(400).json({
			error: "invalid_request",
			error_description: "The request body must be application/json",
		});
		return;
	}
	next();
};
