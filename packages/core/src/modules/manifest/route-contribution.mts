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

import type {
  ErrorRequestHandler,
  RequestHandler,
  Router,
} from "express";

/**
 * Express-compatible route handler shape. Per A2-α §4.6 + A2-β §5.7
 * (forward-deferred): the union covers `Router | RequestHandler |
 * ErrorRequestHandler`. core declares `express` as an optional peer
 * dependency. Modules that contribute routes consume Express via the
 * peer; core imports the type-only via `import type`.
 */
export type RouteHandler = Router | RequestHandler | ErrorRequestHandler;

/**
 * A route contribution. Per A2-α §4.6:
 * - `mountPath` MUST start with "/".
 * - `handler` is the Express-compatible router or middleware.
 * - `id` is an optional collision-identity hint. Two RouteContributions
 *   with the same `id` MUST throw at boot. Two with the same `mountPath`
 *   and no `id` SHOULD throw.
 *
 * The handler's interior is opaque to the boot planner per A2-α §4.7
 * (handler opacity is structural, not a defect).
 */
export interface RouteContribution {
  readonly mountPath: string;
  readonly handler: RouteHandler;
  readonly id?: string;
}

/**
 * Factory producing a RouteContribution from typed deps. Used when the
 * route handler must close over typed deps (per A2-α §4.6).
 */
export type RouteContributionFactory<Deps> = (
  deps: Deps,
) => RouteContribution | Promise<RouteContribution>;

/**
 * Per-entry shape inside `contributes.routes`. Either a static
 * RouteContribution value (dep-free routes) or a factory returning one
 * (dep-using routes). Per A2-α §4.6 Amendment 1.
 */
export type RouteContributionEntry<Deps> =
  | RouteContribution
  | RouteContributionFactory<Deps>;
