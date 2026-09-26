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
/** The modes the route layer understands, in declaration order. */
export const FEDERATION_RESPONSE_MODES = ["query", "form_post"];
/**
 * The mode assumed for a provider that declares none — i.e. every federation
 * written against the pre-Apple contract.
 */
export const DEFAULT_FEDERATION_RESPONSE_MODE = "query";
/**
 * Read a provider's declared response mode, falling back to
 * {@link DEFAULT_FEDERATION_RESPONSE_MODE}.
 *
 * An unrecognised value is treated as the default rather than forwarded. A
 * federation adapter is a third-party extension point reached across an
 * untyped boundary (the same reasoning `mergeFederatedClaims` applies to
 * `mapClaims`), so a provider compiled against a different version of this
 * contract must not be able to push an arbitrary token into the upstream
 * authorization request, nor to unlock the POST callback by naming a mode this
 * router has no handler for.
 */
export const resolveFederationResponseMode = (provider) => {
    const declared = provider.responseMode;
    return FEDERATION_RESPONSE_MODES.includes(declared)
        ? declared
        : DEFAULT_FEDERATION_RESPONSE_MODE;
};
