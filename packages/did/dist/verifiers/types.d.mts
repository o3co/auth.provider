import type { ExtractedKey } from "../resolver/extractKey.mjs";
export interface ParsedMessage {
    did: string;
    timestamp: string;
    nonce: string;
    audience?: string;
}
export interface VerificationContext {
    body: Record<string, unknown>;
    did: string;
    resolvedKey: ExtractedKey;
}
export type VerificationResult = {
    valid: true;
    subject: string;
    audience?: string;
    parsedMessage: ParsedMessage;
} | {
    valid: false;
    error: string;
    errorDescription: string;
};
export interface SignatureVerifier {
    verify(ctx: VerificationContext): Promise<VerificationResult>;
}
//# sourceMappingURL=types.d.mts.map