import { exportJWK } from "jose";
export const createRouter = (express, keyStore) => {
    const router = express.Router();
    router.get("/.well-known/jwks.json", async (_req, res) => {
        if (keyStore.algorithm === "HS256") {
            return res.sendStatus(404);
        }
        const managedKeys = await keyStore.getVerificationKeys();
        const keys = await Promise.all(managedKeys.map(async (mk) => {
            const jwk = await exportJWK(mk.publicKey);
            return { ...jwk, kid: mk.kid, use: "sig", alg: keyStore.algorithm };
        }));
        return res.json({ keys });
    });
    return router;
};
