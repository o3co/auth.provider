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
import { defineModule } from "../modules/manifest/index.mjs";
import { createMemoryWebAuthnCredentialStore } from "./memory.mjs";
/**
 * Built-in module that provides the in-process memory WebAuthnCredentialStore.
 * Test + dev only — no persistence across restarts. Ships in
 * @o3co/auth-provider-core.
 */
export const memoryWebAuthnCredentialStoreModule = defineModule({
    name: "core-webauthn-credential-store-memory",
    provides: {
        webauthnCredentialStore: () => createMemoryWebAuthnCredentialStore(),
    },
});
