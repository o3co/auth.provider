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

import { expectTypeOf, it } from "vitest";
import type {
  HttpMethod,
  RouteAdvertisement,
  RouteContribution,
  RouteHandler,
} from "../route-contribution.mjs";

it("HttpMethod is the 9-method literal union", () => {
  expectTypeOf<HttpMethod>().toEqualTypeOf<
    | "GET"
    | "HEAD"
    | "POST"
    | "PUT"
    | "PATCH"
    | "DELETE"
    | "OPTIONS"
    | "CONNECT"
    | "TRACE"
  >();
});

it("RouteAdvertisement declares method + path", () => {
  expectTypeOf<RouteAdvertisement>().toEqualTypeOf<{
    readonly method: HttpMethod;
    readonly path: string;
  }>();
});

it("RouteContribution accepts an optional routes advertisement list", () => {
  const contrib: RouteContribution = {
    mountPath: "/api",
    handler: {} as RouteHandler,
    routes: [{ method: "GET", path: "/health" }],
  };
  expectTypeOf(contrib).toMatchTypeOf<RouteContribution>();
  // routes field is optional readonly array of RouteAdvertisement
  type RoutesType = RouteContribution["routes"];
  expectTypeOf<RoutesType>().toEqualTypeOf<
    readonly RouteAdvertisement[] | undefined
  >();
});

it("RouteContribution accepts optional before/after token arrays without an own id", () => {
  const contrib: RouteContribution = {
    mountPath: "/api/v1",
    handler: {} as RouteHandler,
    before: ["auth-router"],
    after: ["cors-router"],
    // id is intentionally absent
  };
  expectTypeOf(contrib).toMatchTypeOf<RouteContribution>();

  type BeforeType = RouteContribution["before"];
  type AfterType = RouteContribution["after"];
  expectTypeOf<BeforeType>().toEqualTypeOf<readonly string[] | undefined>();
  expectTypeOf<AfterType>().toEqualTypeOf<readonly string[] | undefined>();
});
