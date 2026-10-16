import { randomBytes, scryptSync } from "node:crypto";
import type { ClientRecord } from "./contract.ts";
import { secretSection } from "./methods.ts";

/** A client record as the operator registers it. */
export type RegisteredClient = ClientRecord;

export interface TestClient {
	readonly id: string;
	readonly method?: string;
	/** Metadata sections, as the modules that own them build them. */
	readonly sections?: Readonly<Record<string, unknown>>;
}

const unpadded = (bytes: Buffer) => bytes.toString("base64").replace(/=+$/, "");

/** The secret of a confidential client made by `confidentialClient`. */
export const clientSecret = (id: string) => `${id}-secret`;

/** A confidential client with the secret `clientSecret(id)`; the method is client_secret_post unless set. */
export function confidentialClient(client: TestClient): RegisteredClient {
	// A scrypt hash at the cheapest work allowed, built here: a module's ./testing may not import another's.
	const salt = randomBytes(16);
	const key = scryptSync(clientSecret(client.id), salt, 32, { N: 1024, r: 8, p: 1 });
	const hash = `$scrypt$ln=10,r=8,p=1$${unpadded(salt)}$${unpadded(key)}`;
	return {
		id: client.id,
		kind: "confidential",
		method: client.method ?? "client_secret_post",
		sections: { [secretSection.name]: { hash }, ...client.sections },
	};
}

export function publicClient(client: TestClient): RegisteredClient {
	return {
		id: client.id,
		kind: "public",
		method: client.method ?? "none",
		sections: { ...client.sections },
	};
}

/** The clients part of a test's configuration. */
export function clientsConfig(registered: readonly RegisteredClient[]) {
	return { clients: { registered } };
}
