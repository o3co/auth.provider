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

import express, { type RequestHandler, type Response } from "express";

/** The one content type the parser reads. */
const JSON_TYPE = "application/json";

/** The largest body the package reads. */
const LIMIT = "100kb";

/** A parser of a JSON request body within the package's limit. */
export const jsonBody = (): RequestHandler => express.json({ type: JSON_TYPE, limit: LIMIT });

const refuseNotJson = (res: Response): void => {
	res.status(400).json({
		error: "invalid_request",
		error_description: "The request body must be application/json",
	});
};

/**
 * Whether a body a parser produced carries nothing: no value, an empty string
 * or buffer, or an object with no fields (what a form parser makes of an
 * empty body). Judged on the parsed value, since the bytes are gone.
 */
const parsedEmpty = (body: unknown): boolean =>
	body === undefined ||
	body === null ||
	body === "" ||
	(typeof body === "object" && Object.keys(body).length === 0);

/**
 * A body something in front of the provider's routes already read — a body
 * parser the host installs (which marks it `_body`), or any reader that took
 * the stream to its end — is judged by the content type it was sent with: a
 * JSON body passes as JSON, and any other body passes only when what was made
 * of it carries nothing; otherwise `400 invalid_request`. A body nothing has
 * read goes on to the package's own readers.
 */
const judgeBodyReadUpstream: RequestHandler = (req, res, next) => {
	const readUpstream = (req as { _body?: unknown })._body === true || req.readableEnded;
	if (readUpstream && !req.is(JSON_TYPE) && !parsedEmpty(req.body)) {
		refuseNotJson(res);
		return;
	}
	next();
};

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
			refuseNotJson(res);
			return;
		}
		req.body = undefined;
	}
	next();
};

/**
 * The body as the admission in front of the registration routes reads it:
 * to its end, whatever its framing, before anything after runs. A body read
 * before the provider's routes is judged as it was read. Otherwise a JSON
 * body is parsed as the routes parse it, and any other body is read within
 * the same limit and refused with `400 invalid_request` when it has bytes,
 * since the routes would not read it. A request with no body, or an empty
 * one, passes.
 */
export const wholeBody = (): RequestHandler[] => [
	judgeBodyReadUpstream,
	jsonBody(),
	remainingBody(),
	refuseBytesNotJson,
];
