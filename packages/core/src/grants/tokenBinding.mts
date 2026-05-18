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
 */
import type { Confirmation } from "./confirmation.mjs";

/**
 * Sender-constrained binding established by a transport-layer mechanism.
 * Core owns only the cross-cutting shape (discriminator + `cnf` claim);
 * mechanism packages extend with their own evidence fields. See Wave 2
 * Token-binding Cluster spec §4.2.
 *
 * Extension boundary: downstream MAY add a new `kind` and evidence
 * fields by extending this interface; the `confirmation` claim itself
 * MUST be one of the variants in `Confirmation` (RFC 7800 / IANA
 * registry domain).
 */
export interface TokenBinding {
	readonly kind: string;
	readonly confirmation: Confirmation;
}
