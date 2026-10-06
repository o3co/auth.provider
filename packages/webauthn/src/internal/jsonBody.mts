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
 * admission do not read it twice. Internal to the package.
 */

import express, { type RequestHandler } from "express";

/** A parser of a JSON request body within the package's limit. */
export const jsonBody = (): RequestHandler => express.json({ limit: "100kb" });
