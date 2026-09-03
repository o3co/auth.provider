import { errorEnvelope } from "../errors/envelope.mjs";
import "./express.mjs"; // ensure ambient Express.Request augmentation is loaded
const OAUTH_ERROR_CODE_PATTERN = /^[a-z][a-z0-9_]*$/;
const hasOAuthErrorCode = (err) => typeof err === "object" &&
    err !== null &&
    "code" in err &&
    typeof err.code === "string" &&
    OAUTH_ERROR_CODE_PATTERN.test(err.code);
export const tokenBindingMw = ({ mechanisms, dispatchPolicy, logger, }) => {
    return async (req, res, next) => {
        // Step 1 — validate all presented binding material.
        const successes = [];
        for (const mechanism of mechanisms) {
            let binding;
            try {
                binding = await mechanism.extract(req);
            }
            catch (err) {
                const code = hasOAuthErrorCode(err) ? err.code : `invalid_${mechanism.kind}_proof`;
                logger?.warn({ mechanism: mechanism.kind, code }, "token_binding_proof_invalid");
                res
                    .status(400)
                    .json(errorEnvelope(code, `${mechanism.kind} mechanism rejected the presented material`));
                return;
            }
            if (binding !== null) {
                successes.push({ mechanism, binding });
            }
        }
        // Step 2 — resolve binding by dispatch policy.
        const [firstSuccess] = successes;
        if (!firstSuccess) {
            next();
            return;
        }
        if (dispatchPolicy === "strict-mutual-exclusion") {
            if (successes.length > 1) {
                const kinds = successes.map((s) => s.mechanism.kind).join(", ");
                res
                    .status(400)
                    .json(errorEnvelope("invalid_request", `multiple token-binding mechanisms succeeded (${kinds}); strict-mutual-exclusion forbids any overlap`));
                return;
            }
            req.tokenBinding = firstSuccess.binding;
            next();
            return;
        }
        // dispatchPolicy === "intent-explicit"
        const explicit = successes.filter((s) => s.mechanism.intentExplicit);
        if (explicit.length >= 2) {
            const kinds = explicit.map((s) => s.mechanism.kind).join(", ");
            res
                .status(400)
                .json(errorEnvelope("invalid_request", `multiple explicit-intent token-binding mechanisms succeeded (${kinds})`));
            return;
        }
        const [firstExplicit] = explicit;
        if (firstExplicit) {
            req.tokenBinding = firstExplicit.binding;
            next();
            return;
        }
        // All successes are ambient. Stage 1 has exactly one ambient
        // mechanism (mTLS), so `successes.length` is provably 1 here
        // (and `firstSuccess` is its single element). Stage 2+ adding a
        // second ambient mechanism must revisit this first-wins rule —
        // a corresponding test for multi-ambient is intentionally
        // deferred until that second mechanism exists.
        req.tokenBinding = firstSuccess.binding;
        next();
    };
};
