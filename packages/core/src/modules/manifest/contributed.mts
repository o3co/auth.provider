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
 *
 * `applyContributions` awaits every kind, so a factory that needs I/O to build
 * what it contributes — an adapter discovering its issuer's metadata at boot,
 * a mechanism reading a key — is legitimately `async`. The contract says what
 * boot accepts, and every kind boot awaits says it (#626 P1).
 *
 * It does not widen what a consumer reads: the collector holds the awaited
 * value, so `federationProviders` is still a map of `FederationProvider`.
 *
 * Its own module because `contributes-map` and `route-contribution` both name
 * it and the first already imports the second.
 */
export type Contributed<T> = T | Promise<T>;
