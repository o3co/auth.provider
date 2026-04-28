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
 * HTTP method literal union. Covers the 9 standard methods defined in
 * RFC 7231 / RFC 5789.
 *
 * Per A2-β §4.2.
 */
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
 * Fine-grained route advertisement attached to a `RouteContribution`.
 * Enables the boot planner to detect method + path collisions at the
 * sub-router level, independent of `mountPath`.
 *
 * Per A2-β §4.2.
 */
export interface RouteAdvertisement {
  /** HTTP method this advertisement covers. Per A2-β §4.2. */
  readonly method: HttpMethod;
  /**
   * Path relative to the contribution's `mountPath`. MUST start with "/";
   * the boot planner's `validateManifests` stage throws
   * `invalid-route-advertisement-path` otherwise (A2-β §5.1 step 7,
   * §6.1).
   *
   * Per A2-β §4.2.
   */
  readonly path: string;
}

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
 *
 * A2-β §4.2 adds three optional fields:
 * - `routes`: fine-grained advertisement of method + path pairs exposed
 *   by this contribution. The boot planner uses effective
 *   `mountPath + advertisement.path` for collision identity.
 * - `before`: token array of contribution `id`s this contribution must
 *   be mounted before. Resolved by the boot planner's assemble-app stage
 *   §5.6 step 1.
 * - `after`: token array of contribution `id`s this contribution must
 *   be mounted after. Resolved alongside `before`.
 */
export interface RouteContribution {
  readonly mountPath: string;
  readonly handler: RouteHandler;
  readonly id?: string;
  /**
   * Fine-grained route advertisements. Per A2-β §4.2.
   * The boot planner uses these for sub-router collision detection.
   */
  readonly routes?: readonly RouteAdvertisement[];
  /**
   * Contribution `id` tokens this contribution must be mounted before.
   * Per A2-β §4.2; resolved at assemble-app stage §5.6.
   */
  readonly before?: readonly string[];
  /**
   * Contribution `id` tokens this contribution must be mounted after.
   * Per A2-β §4.2; resolved at assemble-app stage §5.6.
   */
  readonly after?: readonly string[];
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
