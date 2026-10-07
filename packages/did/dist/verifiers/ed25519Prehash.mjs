import { extractEd25519PublicKeyBytes } from "./ed25519Utils.mjs";
export class Ed25519PrehashVerifier {
    verifyAsync;
    pathResolver;
    constructor(pathResolver) {
        this.pathResolver = pathResolver;
    }
    async loadVerifyAsync() {
        if (this.verifyAsync)
            return this.verifyAsync;
        const specifier = "@noble/ed25519";
        const mod = this.pathResolver
            ? (await import(this.pathResolver(specifier)))
            : (await import(specifier));
        this.verifyAsync = mod.verifyAsync;
        return this.verifyAsync;
    }
    async verify(ctx) {
        const { body, did, resolvedKey } = ctx;
        // 1. Validate signature and message are present
        if (typeof body.signature !== "string" || !body.signature) {
            return { valid: false, error: "invalid_request", errorDescription: "signature is required" };
        }
        if (typeof body.message !== "string" || !body.message) {
            return { valid: false, error: "invalid_request", errorDescription: "message is required" };
        }
        // 2. Parse message as JSON
        let parsedMessage;
        try {
            parsedMessage = JSON.parse(body.message);
        }
        catch {
            return {
                valid: false,
                error: "invalid_request",
                errorDescription: "message must be valid JSON",
            };
        }
        // 3. Validate message.did matches ctx.did
        if (parsedMessage.did !== did) {
            return {
                valid: false,
                error: "invalid_request",
                errorDescription: "message.did must match did",
            };
        }
        // 4. Extract public key bytes from resolvedKey
        let publicKeyBytes;
        try {
            publicKeyBytes = extractEd25519PublicKeyBytes(resolvedKey);
        }
        catch (err) {
            return {
                valid: false,
                error: "invalid_request",
                errorDescription: err instanceof Error ? err.message : "invalid public key",
            };
        }
        // 5. Compute SHA-256 hash of message, then verify Ed25519 signature against the hash
        try {
            const verifyAsync = await this.loadVerifyAsync();
            const signatureBytes = Buffer.from(body.signature, "base64");
            const messageBytes = new TextEncoder().encode(body.message);
            const hashBuffer = await crypto.subtle.digest("SHA-256", messageBytes);
            const hash = new Uint8Array(hashBuffer);
            const valid = await verifyAsync(signatureBytes, hash, publicKeyBytes);
            if (!valid) {
                return {
                    valid: false,
                    error: "invalid_grant",
                    errorDescription: "signature verification failed",
                };
            }
        }
        catch {
            return {
                valid: false,
                error: "invalid_grant",
                errorDescription: "signature verification error",
            };
        }
        // 6. Return success
        return { valid: true, subject: did, audience: parsedMessage.audience, parsedMessage };
    }
}
