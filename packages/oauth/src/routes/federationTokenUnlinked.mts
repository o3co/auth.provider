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
 * A link with no record the route can serve, answered `404
 * federation_not_linked`. The session's index is left as it is: removing the
 * link here could remove one a concurrent relink just added. A link with no
 * record holds no credential; federation logout removes it, and it ends with
 * the session.
 */

import { sanitizeErrorText } from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { FederationTokenContext } from "./federationTokenContext.mjs";

/**
 * The answer for a record that is missing, or that a store judging its
 * records would have answered as missing.
 */
export const answerUnlinkedRecord = (ctx: Pick<FederationTokenContext, "res" | "name">): Response =>
	ctx.res.status(404).json({
		error: "federation_not_linked",
		error_description: sanitizeErrorText(`federation '${ctx.name}' tokens not found`),
	});
