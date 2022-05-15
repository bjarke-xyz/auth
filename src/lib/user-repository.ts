import { nanoid } from "nanoid";
import { WorkerEnv } from "../types";
import { User } from "./models";
import { hash } from "bcryptjs";

export interface CreateUserRequest {
  email: string;
  password: string;
}

export class UserRepository {
  constructor(private readonly env: WorkerEnv) {}

  async getUser(id: string, blankPassword = true): Promise<User | null> {
    const user = await this.env.KV_AUTH.get<User>(`users:${id}`, "json");
    if (user && blankPassword) {
      user.hashedPassword = "";
    }
    return user;
  }

  async getUserByEmail(
    email: string,
    blankPassword = true
  ): Promise<User | null> {
    const userId = await this.env.KV_AUTH.get<{ id: string }>(
      `users#email:${email.toLowerCase()}`,
      "json"
    );
    if (!userId) {
      return null;
    }
    return this.getUser(userId.id, blankPassword);
  }

  async createUser(
    createUserRequest: CreateUserRequest
  ): Promise<User | string> {
    const id = nanoid();
    const email = createUserRequest.email;
    const existingUser = await this.env.KV_AUTH.get(
      `users#email:${email.toLowerCase()}`
    );
    if (existingUser) {
      return "Email in use";
    }
    const hashedPassword = await hash(createUserRequest.password, 10);
    const user: User = {
      id,
      email,
      hashedPassword,
    };
    await this.env.KV_AUTH.put(`users:${id}`, JSON.stringify(user));
    await this.env.KV_AUTH.put(
      `users#email:${email.toLowerCase()}`,
      JSON.stringify({ id })
    );
    return user;
  }
}
