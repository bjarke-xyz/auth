/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `wrangler dev src/index.ts` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `wrangler publish src/index.ts --name my-worker` to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

import { Router } from "itty-router";
import { createUser, getUser } from "./handlers/users";
import { UserRepository } from "./lib/user-repository";
import { IttyRequest, WorkerEnv } from "./types";

const router = Router();
router.get(
  "/users/me",
  (req: IttyRequest, env: WorkerEnv, context: EventContext<any, any, any>) =>
    getUser(req, context, new UserRepository(env))
);

router.post(
  "/users",
  (req: IttyRequest, env: WorkerEnv, context: EventContext<any, any, any>) =>
    createUser(req, context, env, new UserRepository(env))
);

router.all("*", () => new Response("Not found", { status: 404 }));
export default {
  fetch: router.handle,
  async scheduled(
    event: ScheduledEvent,
    env: WorkerEnv,
    context: EventContext<any, any, any>
  ) {},
};
