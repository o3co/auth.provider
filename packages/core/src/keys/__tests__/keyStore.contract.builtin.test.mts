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
 * The in-config stores against the shared contract (#303).
 *
 * Running the two implementations that already shipped is what makes the
 * contract a description of the port rather than a description of the new
 * adapter. If a rule only the remote store satisfies were written into it, one
 * of these would fail here.
 */

import { exportPKCS8, exportSPKI, generateKeyPair } from "jose";
import { createAsymmetricKeyStore, createSymmetricKeyStore } from "#/keys/KeyStore.mjs";
import { runKeyStoreContract } from "./keyStore.contract.mjs";

const SECRET = "test-secret-at-least-32-bytes-long!!";
const PREVIOUS_SECRET = "another-secret-at-least-32-bytes!!!!";

runKeyStoreContract("createSymmetricKeyStore (HS256)", {
	algorithm: "HS256",
	activeKid: "v2",
	previousKid: "v1",
	expiredKid: "v0",
	create: () =>
		createSymmetricKeyStore(SECRET, "v2", [
			{ kid: "v1", secret: PREVIOUS_SECRET, expiresAt: new Date(Date.now() + 600_000) },
			{ kid: "v0", secret: PREVIOUS_SECRET, expiresAt: new Date(Date.now() - 1) },
		]),
});

const ed = await generateKeyPair("EdDSA", { extractable: true });
const edPrev = await generateKeyPair("EdDSA", { extractable: true });
const activePkcs8 = await exportPKCS8(ed.privateKey);
const activeSpki = await exportSPKI(ed.publicKey);
const prevSpki = await exportSPKI(edPrev.publicKey);

runKeyStoreContract("createAsymmetricKeyStore (EdDSA)", {
	algorithm: "EdDSA",
	activeKid: "v2",
	previousKid: "v1",
	expiredKid: "v0",
	create: () =>
		createAsymmetricKeyStore({
			algorithm: "EdDSA",
			kid: "v2",
			privateKeyPem: activePkcs8,
			publicKeyPem: activeSpki,
			previousKeys: [
				{ kid: "v1", publicKeyPem: prevSpki, expiresAt: new Date(Date.now() + 600_000) },
				{ kid: "v0", publicKeyPem: prevSpki, expiresAt: new Date(Date.now() - 1) },
			],
		}),
});
