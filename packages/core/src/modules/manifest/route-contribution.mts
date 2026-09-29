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

import type { ErrorRequestHandler, RequestHandler, Router } from "express";
import type { Contributed } from "./contributed.mjs";

/**
 * Express-compatible route handler. core declares `express` as an optional
 * peer dependency and imports its types only.
 */
export type RouteHandler = Router | RequestHandler | ErrorRequestHandler;

/** The nine standard HTTP methods (RFC 7231, RFC 5789). */
export type HttpMethod =
	| "GET"
	| "HEAD"
	| "POST"
	| "PUT"
	| "PATCH"
	| "DELETE"
	| "OPTIONS"
	| "CONNECT"
	| "TRACE";

/**
 * A method + path a `RouteContribution` exposes, so the boot planner can
 * detect collisions below `mountPath`.
 */
export interface RouteAdvertisement {
	readonly method: HttpMethod;
	/**
	 * Path relative to the contribution's `mountPath`. MUST start with "/";
	 * boot rejects it otherwise (`invalid-route-advertisement-path`).
	 */
	readonly path: string;
}

/**
 * A route contribution.
 * - `mountPath` MUST start with "/".
 * - `id` is an optional collision identity: two contributions with the same
 *   `id` throw at boot; two with the same `mountPath` and no `id` SHOULD.
 *
 * The handler's interior is opaque to the boot planner; `routes` is how a
 * contribution exposes what it serves.
 */
export interface RouteContribution {
	readonly mountPath: string;
	readonly handler: RouteHandler;
	readonly id?: string;
	/** Method + path pairs served; collision identity is `mountPath + path`. */
	readonly routes?: readonly RouteAdvertisement[];
	/** Contribution `id`s this contribution must be mounted before. */
	readonly before?: readonly string[];
	/** Contribution `id`s this contribution must be mounted after. */
	readonly after?: readonly string[];
}

/** Builds a RouteContribution whose handler closes over typed deps. */
export type RouteContributionFactory<Deps> = (deps: Deps) => Contributed<RouteContribution>;

/**
 * One entry of `contributes.routes`: a static RouteContribution (no deps) or
 * a factory returning one.
 */
export type RouteContributionEntry<Deps> = RouteContribution | RouteContributionFactory<Deps>;
