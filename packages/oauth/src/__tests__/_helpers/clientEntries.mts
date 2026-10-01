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
import type { ClientEntry, ClientEntrySchema } from "@o3co/auth-provider-core";
import type { z } from "zod";

/**
 * Client entries as a registration file gives them: the schema's input, its
 * defaults left out. `InMemoryClientRepository` parses each entry, so it takes
 * this form, though its parameter is typed with the schema's output.
 */
export const clientEntries = (
	entries: Iterable<readonly [string, z.input<typeof ClientEntrySchema>]>,
): Map<string, ClientEntry> => new Map(entries) as Map<string, ClientEntry>;
