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

/**
 * RFC 7800 confirmation claim, narrowed to the binding methods this
 * library ships in Stage 1. Adding a future variant (e.g. RFC 9421
 * `jwk`) is a core semver-minor extension of this union — see Wave 2
 * Token-binding Cluster spec §4.3.
 */
export type Confirmation = { readonly jkt: string } | { readonly "x5t#S256": string };
