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
 * What a contribution factory may answer with: the value, or a promise of it.
 * `applyContributions` awaits every kind, so a factory needing boot-time I/O
 * (an adapter discovering issuer metadata, a mechanism reading a key) may be
 * `async`. Consumers still read the awaited value: `federationProviders` is a
 * map of `FederationProvider`.
 *
 * Its own module because `contributes-map` and `route-contribution` both name
 * it and the first already imports the second.
 */
export type Contributed<T> = T | Promise<T>;
