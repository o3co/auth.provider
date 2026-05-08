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

import type { Request, Response, Router } from "express";
import type { MfaProviderFactory, MfaResumeState, MfaTransactionStore } from "./types.mjs";

export interface MfaRouteDeps {
	providerFactory: MfaProviderFactory;
	transactionStore: MfaTransactionStore;
	onAuthorizeResume(
		req: Request,
		res: Response,
		resume: Extract<MfaResumeState, { flow: "authorize" }> & { subject: string },
	): Promise<void>;
	onFederationResume(
		req: Request,
		res: Response,
		resume: Extract<MfaResumeState, { flow: "federation" }> & { subject: string },
	): Promise<void>;
	onLoginResume(
		req: Request,
		res: Response,
		resume: Extract<MfaResumeState, { flow: "login" }> & { subject: string },
	): Promise<void>;
}

export function createMfaRouter(express: { Router: () => Router }, deps: MfaRouteDeps): Router {
	const router = express.Router();

	router.post("/auth/mfa/verify", async (req: Request, res: Response) => {
		const body = req.body as { transaction_id?: unknown; proof?: unknown };
		const transactionId = typeof body.transaction_id === "string" ? body.transaction_id : null;
		if (!transactionId) {
			return res
				.status(400)
				.json({ error: "invalid_request", error_description: "transaction_id required" });
		}
		const tx = await deps.transactionStore.get(transactionId);
		if (!tx) {
			return res.status(400).json({
				error: "invalid_grant",
				error_description: "unknown or expired transaction",
			});
		}
		// Defense in depth: reject expired transactions even if the store implementation
		// did not filter them on load. Implementations MAY filter; core enforces regardless.
		if (tx.expiresAt.getTime() <= Date.now()) {
			await deps.transactionStore.delete(transactionId);
			return res.status(400).json({
				error: "invalid_grant",
				error_description: "unknown or expired transaction",
			});
		}
		// CP-7: provider creation or verification can throw (unregistered kind,
		// backend outage, etc.). Return a controlled 500 JSON instead of
		// letting Express surface an unhandled error. On irrecoverable
		// provider errors we delete the transaction — it cannot be retried
		// meaningfully when the provider isn't available to verify it.
		let result: Awaited<ReturnType<typeof provider.verify>>;
		let provider: Awaited<ReturnType<typeof deps.providerFactory.create>>;
		try {
			provider = await deps.providerFactory.create({ type: tx.providerKind });
			if (provider.kind !== tx.providerKind) {
				await deps.transactionStore.delete(transactionId);
				return res
					.status(500)
					.json({ error: "server_error", error_description: "provider kind mismatch" });
			}
			result = await provider.verify(tx.challengeId, body.proof);
		} catch {
			await deps.transactionStore.delete(transactionId);
			return res.status(500).json({
				error: "server_error",
				error_description: "mfa verification unavailable",
			});
		}
		if (!result.success) {
			return res.status(401).json({
				error: "mfa_failed",
				error_description: result.failureReason ?? "invalid",
			});
		}
		await deps.transactionStore.delete(transactionId);
		switch (tx.resumeState.flow) {
			case "authorize":
				await deps.onAuthorizeResume(req, res, { ...tx.resumeState, subject: tx.subject });
				return;
			case "federation":
				await deps.onFederationResume(req, res, { ...tx.resumeState, subject: tx.subject });
				return;
			case "login":
				await deps.onLoginResume(req, res, { ...tx.resumeState, subject: tx.subject });
				return;
		}
	});

	return router;
}
