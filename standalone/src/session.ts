/**
 * Session manager using Redis
 * Replaces Cloudflare Durable Objects for session state
 */

import Redis from "ioredis";
import { v4 as uuidv4 } from "uuid";
import type { Config } from "./config";

export interface Session {
  id: string;
  userId?: string;
  orgId?: string;
  createdAt: number;
  lastAccessedAt: number;
  data: Record<string, unknown>;
}

export class SessionManager {
  private redis: Redis;
  private prefix = "argus:mcp:session:";
  private ttlSeconds = 3600; // 1 hour

  constructor(config: Config) {
    this.redis = new Redis(config.REDIS_URL, {
      maxRetriesPerRequest: 3,
      lazyConnect: true,
    });

    this.redis.on("error", (err: Error) => {
      console.error("Redis error:", err);
    });
  }

  async connect(): Promise<void> {
    await this.redis.connect();
  }

  async createSession(userId?: string, orgId?: string): Promise<Session> {
    const session: Session = {
      id: uuidv4(),
      userId,
      orgId,
      createdAt: Date.now(),
      lastAccessedAt: Date.now(),
      data: {},
    };

    await this.redis.setex(
      this.prefix + session.id,
      this.ttlSeconds,
      JSON.stringify(session)
    );

    return session;
  }

  async getSession(sessionId: string): Promise<Session | null> {
    const data = await this.redis.get(this.prefix + sessionId);
    if (!data) return null;

    const session = JSON.parse(data) as Session;

    // Update last accessed time
    session.lastAccessedAt = Date.now();
    await this.redis.setex(
      this.prefix + sessionId,
      this.ttlSeconds,
      JSON.stringify(session)
    );

    return session;
  }

  async updateSession(
    sessionId: string,
    updates: Partial<Session>
  ): Promise<Session | null> {
    const session = await this.getSession(sessionId);
    if (!session) return null;

    const updated = { ...session, ...updates, lastAccessedAt: Date.now() };
    await this.redis.setex(
      this.prefix + sessionId,
      this.ttlSeconds,
      JSON.stringify(updated)
    );

    return updated;
  }

  async setSessionData(
    sessionId: string,
    key: string,
    value: unknown
  ): Promise<void> {
    const session = await this.getSession(sessionId);
    if (!session) return;

    session.data[key] = value;
    await this.redis.setex(
      this.prefix + sessionId,
      this.ttlSeconds,
      JSON.stringify(session)
    );
  }

  async getSessionData(sessionId: string, key: string): Promise<unknown> {
    const session = await this.getSession(sessionId);
    return session?.data[key];
  }

  async deleteSession(sessionId: string): Promise<void> {
    await this.redis.del(this.prefix + sessionId);
  }

  async healthCheck(): Promise<{ healthy: boolean; error?: string }> {
    try {
      await this.redis.ping();
      return { healthy: true };
    } catch (error) {
      return {
        healthy: false,
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  async close(): Promise<void> {
    await this.redis.quit();
  }
}

/**
 * In-memory session manager for development/testing
 * Does not require Redis
 */
export class InMemorySessionManager {
  private sessions = new Map<string, Session>();

  async createSession(userId?: string, orgId?: string): Promise<Session> {
    const session: Session = {
      id: uuidv4(),
      userId,
      orgId,
      createdAt: Date.now(),
      lastAccessedAt: Date.now(),
      data: {},
    };

    this.sessions.set(session.id, session);
    return session;
  }

  async getSession(sessionId: string): Promise<Session | null> {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.lastAccessedAt = Date.now();
    }
    return session || null;
  }

  async updateSession(
    sessionId: string,
    updates: Partial<Session>
  ): Promise<Session | null> {
    const session = this.sessions.get(sessionId);
    if (!session) return null;

    const updated = { ...session, ...updates, lastAccessedAt: Date.now() };
    this.sessions.set(sessionId, updated);
    return updated;
  }

  async setSessionData(
    sessionId: string,
    key: string,
    value: unknown
  ): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.data[key] = value;
    }
  }

  async getSessionData(sessionId: string, key: string): Promise<unknown> {
    const session = this.sessions.get(sessionId);
    return session?.data[key];
  }

  async deleteSession(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
  }

  async healthCheck(): Promise<{ healthy: boolean }> {
    return { healthy: true };
  }

  async connect(): Promise<void> {}
  async close(): Promise<void> {}
}
