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
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  type AppConfig,
  AppConfigSchema,
  createApp,
  createDefaultFactories,
  createKeyStoreFromConfig,
  oauthSessionModule,
  oauthAuthorizationModule,
} from "@o3co/auth-provider-core";
import { oauthDidModule } from "@o3co/auth-provider-did";
import { oauthModule } from "@o3co/auth-provider-oauth";
import { sessionModule } from "@o3co/auth-provider-session";
import { registerBuiltinRepositories } from "@o3co/auth-provider-repositories";
import { gracefulShutdown } from "@o3co/auth.utils";
import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { RedisStore } from "connect-redis";
import express from "express";
import session from "express-session";
import helmet from "helmet";
import passport from "passport";
import { createClient } from "redis";

import logger from "#/logger.mjs";

const config: AppConfig = validate(
  parseFile(fileURLToPath(new URL("../config/application.conf", import.meta.url))),
  AppConfigSchema,
);

await (async (): Promise<void> => {
  // Initialize repositories via factory
  const appDir = path.dirname(fileURLToPath(import.meta.url));
  const { clientFactory, userFactory, codeFactory } = createDefaultFactories();
  registerBuiltinRepositories({ userFactory, codeFactory });

  const clientRepository = await clientFactory.create({
    ...config.clients.client,
    path: path.resolve(appDir, "..", config.clients.client.path),
  });
  const userRepository = await userFactory.create(config.clients.user);
  const codeRepository = await codeFactory.create(config.clients.code);

  const app = express();

  app.set("trust proxy", config.http.trustProxy);
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'none'"],
          frameAncestors: ["'none'"],
        },
      },
    }),
  );

  const storageType = config.session.storage.type;
  let store: session.Store | undefined;
  switch (storageType) {
    case "redis":
      {
        const options = config.session.storage.redis;
        const redisClient = createClient({ url: options.url, password: options.password });
        await redisClient.connect();
        store = new RedisStore({ client: redisClient });
      }
      break;
    case "memory":
      store = undefined; // Use default in-memory store
      break;
    default:
      throw new Error(`Unsupported session storage type: ${storageType}`);
  }

  app.use(
    session({
      secret: config.session.secret,
      resave: false,
      saveUninitialized: false,
      store,
      cookie: {
        path: "/",
        httpOnly: true,
        secure: config.session.secure,
        maxAge: config.session.maxAge,
        sameSite: config.session.sameSite,
        domain: config.session.domain || undefined,
      },
    }),
  );

  // Initialize Passport middleware (strategies are registered by modules during init)
  app.use(passport.initialize());
  app.use(passport.session());

  // Initialize KeyStore
  const keyStore = await createKeyStoreFromConfig(config.oauth.jwt);

  // Create app with module composition
  const { init, router, grantRegistry } = createApp(express, {
    pathResolver: import.meta.resolve,
    config,
    keyStore,
    modules: [
      oauthModule({ clientRepository, codeRepository, express }),
      sessionModule({ userRepository, express }),
      oauthSessionModule({ clientRepository }),
      oauthAuthorizationModule({ codeRepository }),
      oauthDidModule,
    ],
  });

  // Initialize all modules (async — resolves external deps via pathResolver)
  await init();

  app.use(router);

  const server = app.listen(config.http.port, (): void => {
    logger.info(`Server is running on http://localhost:${config.http.port}`);
  });

  gracefulShutdown(server, () => grantRegistry.cleanup());
})();
