import { Request as IttyRouterRequest } from "itty-router";

export type WorkerEnv = {
  KV_AUTH: KVNamespace;
  AUTH_ADMIN_KEY: string;
};

export type IttyRequest = Request & IttyRouterRequest;
