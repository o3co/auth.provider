# @o3co/auth.utils

[![CI](https://github.com/o3co/auth.utils/actions/workflows/ci.yml/badge.svg)](https://github.com/o3co/auth.utils/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@o3co/auth.utils)](https://www.npmjs.com/package/@o3co/auth.utils)
[![codecov](https://codecov.io/gh/o3co/auth.utils/graph/badge.svg)](https://codecov.io/gh/o3co/auth.utils)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Shared utilities for auth.* services.

## Install

```bash
pnpm add @o3co/auth.utils
```

## Logger

```typescript
import { createLogger } from "@o3co/auth.utils";

const logger = createLogger("my-service");
logger.info("started");
logger.info({ requestId: "abc" }, "request received");
```

Default backend: pino (if installed), console (fallback). Inject your own via `createLogger("name", { logger: myLogger })`.

## Graceful Shutdown

```typescript
import { gracefulShutdown } from "@o3co/auth.utils";

const server = app.listen(3000);
gracefulShutdown(server);
```

## Express Middleware

```typescript
import {
  createHealthcheckRouter,
  createRequestIdMiddleware,
  extractBearerToken,
} from "@o3co/auth.utils/express";

app.use(createHealthcheckRouter());
app.use(createRequestIdMiddleware());

// In a route handler:
const result = extractBearerToken(req.get("authorization"));
```

## License

Apache-2.0 — Copyright 2026 1o1 Co. Ltd.
