export const createRouter = (express) => {
    const router = express.Router();
    router.get("/_healthcheck", (_req, res) => {
        res.json({ code: 200, message: "healthy" });
    });
    return router;
};
