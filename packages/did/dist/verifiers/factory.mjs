import { JwsVerifier } from "./jws.mjs";
import { VerifierRegistry } from "./registry.mjs";
const JWS_ALG_MAP = {
    ed25519_jws: "EdDSA",
    es256_jws: "ES256",
    es256k_jws: "ES256K",
};
export function createDefaultVerifierRegistry() {
    const registry = new VerifierRegistry();
    registry.register("ed25519_raw", async (pathResolver) => {
        try {
            const { Ed25519RawVerifier } = await import("./ed25519Raw.mjs");
            return new Ed25519RawVerifier(pathResolver);
        }
        catch (err) {
            const code = typeof err === "object" && err !== null && "code" in err
                ? err.code
                : undefined;
            const message = err instanceof Error ? err.message : String(err);
            if ((code === "ERR_MODULE_NOT_FOUND" || code === "MODULE_NOT_FOUND") &&
                message.includes("@noble/ed25519")) {
                throw new Error("ed25519_raw algorithm requires @noble/ed25519 package. " +
                    "Install it with: pnpm add @noble/ed25519 — or switch to a JWS algorithm (ed25519_jws, es256_jws, es256k_jws).");
            }
            throw err;
        }
    });
    registry.register("ed25519_prehash", async (pathResolver) => {
        try {
            const { Ed25519PrehashVerifier } = await import("./ed25519Prehash.mjs");
            return new Ed25519PrehashVerifier(pathResolver);
        }
        catch (err) {
            const code = typeof err === "object" && err !== null && "code" in err
                ? err.code
                : undefined;
            const message = err instanceof Error ? err.message : String(err);
            if ((code === "ERR_MODULE_NOT_FOUND" || code === "MODULE_NOT_FOUND") &&
                message.includes("@noble/ed25519")) {
                throw new Error("ed25519_prehash algorithm requires @noble/ed25519 package. " +
                    "Install it with: pnpm add @noble/ed25519 — or switch to a JWS algorithm (ed25519_jws, es256_jws, es256k_jws).");
            }
            throw err;
        }
    });
    registry.register("ed25519_jws", async () => new JwsVerifier(JWS_ALG_MAP.ed25519_jws));
    registry.register("es256_jws", async () => new JwsVerifier(JWS_ALG_MAP.es256_jws));
    registry.register("es256k_jws", async () => new JwsVerifier(JWS_ALG_MAP.es256k_jws));
    return registry;
}
export async function createVerifier(algorithm, pathResolver) {
    const registry = createDefaultVerifierRegistry();
    const factory = registry.get(algorithm);
    if (!factory) {
        throw new Error(`Unsupported algorithm: "${algorithm}". Supported: ${registry.algorithms().join(", ")}`);
    }
    return factory(pathResolver);
}
