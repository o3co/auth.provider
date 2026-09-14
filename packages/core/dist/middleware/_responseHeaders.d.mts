import type { Response } from "express";
/**
 * The response headers a token-binding outcome asks for (#530): a refusal
 * (an error carrying `responseHeaders`) or an accepted binding
 * (`TokenBinding.responseHeaders`). Only string-valued entries count — a
 * mechanism cannot smuggle a non-header through.
 */
export declare const responseHeadersOf: (source: unknown) => Readonly<Record<string, string>>;
/** Set every header {@link responseHeadersOf} finds on `source`. */
export declare const applyResponseHeaders: (res: Response, source: unknown) => void;
/** The OAuth error `code` a thrown refusal carries, or `undefined`. */
export declare const oauthErrorCodeOf: (err: unknown) => string | undefined;
/**
 * The retry instruction a refusal states (`TokenBindingRefusal.retryInstruction`),
 * or `undefined` for a verdict. Only a non-empty string beside an OAuth code
 * counts: an instruction with no code to answer under is not one.
 */
export declare const retryInstructionOf: (err: unknown) => string | undefined;
//# sourceMappingURL=_responseHeaders.d.mts.map