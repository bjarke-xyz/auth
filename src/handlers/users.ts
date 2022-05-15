import { CreateUserRequest, UserRepository } from "../lib/user-repository";
import { IttyRequest, WorkerEnv } from "../types";
import { compare } from "bcryptjs";
import { isString } from "lodash";

export async function getUser(
  request: IttyRequest,
  context: EventContext<any, any, any>,
  userRepository: UserRepository
): Promise<Response> {
  const authHeaderValue = request.headers.get("Authorization");
  if (!authHeaderValue) {
    return new Response("Missing authorization header", { status: 401 });
  }

  const decoded = atob(authHeaderValue.split(" ")[1]?.trim());
  const [userId, password] = decoded.split(":");
  const user = await userRepository.getUser(userId, false);
  if (!user) {
    return new Response("User not found", { status: 401 });
  }
  const passwordValid = await compare(password, user.hashedPassword);
  if (!passwordValid) {
    return new Response("Invalid password", { status: 401 });
  }

  user.hashedPassword = "";
  return new Response(JSON.stringify(user));
}

export async function createUser(
  request: IttyRequest,
  context: EventContext<any, any, any>,
  env: WorkerEnv,
  userRepository: UserRepository
): Promise<Response> {
  const authHeaderValue = request.headers.get("Authorization");
  if (!authHeaderValue) {
    return new Response("Missing auth header", { status: 401 });
  }
  if (authHeaderValue !== env.AUTH_ADMIN_KEY) {
    return new Response("Wrong auth header", { status: 401 });
  }

  let createUserRequest: CreateUserRequest | null = null;
  try {
    createUserRequest = await request.json<CreateUserRequest>();
  } catch (error) {
    console.error("createUser: could not parse json", error);
    return new Response("Could not create user", { status: 500 });
  }

  if (!createUserRequest?.password) {
    return new Response("Missing password", {
      status: 400,
    });
  }
  if (!createUserRequest?.email) {
    return new Response("Missing email", {
      status: 400,
    });
  }

  const user = await userRepository.createUser(createUserRequest);
  if (isString(user)) {
    return new Response(`Could not create user: ${user}`, { status: 500 });
  }
  user.hashedPassword = "";
  return new Response(JSON.stringify(user));
}
