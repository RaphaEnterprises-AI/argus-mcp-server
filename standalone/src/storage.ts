/**
 * Storage adapter for screenshots and artifacts
 * Uses MinIO/S3 for self-hosted deployments
 */

import { Client as MinioClient } from "minio";
import { createHmac } from "crypto";
import type { Config } from "./config";

export interface StorageAdapter {
  storeScreenshot(
    data: Buffer | string,
    sessionId: string,
    identifier: string | number,
    metadata?: Record<string, string>
  ): Promise<{ success: boolean; url?: string; key?: string; error?: string }>;

  getScreenshot(key: string): Promise<Buffer | null>;

  generateSignedUrl(key: string, expirySeconds?: number): Promise<string>;

  healthCheck(): Promise<{ healthy: boolean; error?: string }>;
}

export class MinIOStorageAdapter implements StorageAdapter {
  private client: MinioClient;
  private bucket: string;
  private baseUrl: string;
  private jwtSecret?: string;

  constructor(config: Config) {
    this.client = new MinioClient({
      endPoint: config.MINIO_ENDPOINT.split(":")[0],
      port: parseInt(config.MINIO_ENDPOINT.split(":")[1] || "9000"),
      useSSL: config.MINIO_SECURE,
      accessKey: config.MINIO_ACCESS_KEY,
      secretKey: config.MINIO_SECRET_KEY,
      region: config.MINIO_REGION,
    });
    this.bucket = config.MINIO_BUCKET;
    this.baseUrl = `http${config.MINIO_SECURE ? "s" : ""}://${config.MINIO_ENDPOINT}`;
    this.jwtSecret = config.JWT_SECRET;
  }

  async ensureBucket(): Promise<void> {
    const exists = await this.client.bucketExists(this.bucket);
    if (!exists) {
      await this.client.makeBucket(this.bucket);
      console.log(`Created bucket: ${this.bucket}`);
    }
  }

  async storeScreenshot(
    data: Buffer | string,
    sessionId: string,
    identifier: string | number,
    metadata?: Record<string, string>
  ): Promise<{ success: boolean; url?: string; key?: string; error?: string }> {
    try {
      const key = `mcp-screenshots/${sessionId}/${identifier}.png`;

      // Convert base64 string to Buffer if needed
      let buffer: Buffer;
      if (typeof data === "string") {
        // Remove data URL prefix if present
        const cleanBase64 = data.replace(/^data:image\/\w+;base64,/, "");
        buffer = Buffer.from(cleanBase64, "base64");
      } else {
        buffer = data;
      }

      await this.client.putObject(this.bucket, key, buffer, buffer.length, {
        "Content-Type": "image/png",
        ...(metadata || {}),
      });

      const url = await this.generateSignedUrl(key);

      return { success: true, url, key };
    } catch (error) {
      console.error("Failed to store screenshot:", error);
      return {
        success: false,
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  async getScreenshot(key: string): Promise<Buffer | null> {
    try {
      const stream = await this.client.getObject(this.bucket, key);
      const chunks: Buffer[] = [];

      for await (const chunk of stream) {
        chunks.push(chunk as Buffer);
      }

      return Buffer.concat(chunks);
    } catch (error) {
      console.error("Failed to get screenshot:", error);
      return null;
    }
  }

  async generateSignedUrl(key: string, expirySeconds = 3600): Promise<string> {
    // Use MinIO's presigned URL
    return await this.client.presignedGetObject(
      this.bucket,
      key,
      expirySeconds
    );
  }

  async healthCheck(): Promise<{ healthy: boolean; error?: string }> {
    try {
      await this.client.bucketExists(this.bucket);
      return { healthy: true };
    } catch (error) {
      return {
        healthy: false,
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }
}

export class LocalStorageAdapter implements StorageAdapter {
  private basePath: string;

  constructor(basePath = "./screenshots") {
    this.basePath = basePath;
  }

  async storeScreenshot(
    data: Buffer | string,
    sessionId: string,
    identifier: string | number
  ): Promise<{ success: boolean; url?: string; key?: string; error?: string }> {
    const fs = await import("fs/promises");
    const path = await import("path");

    try {
      const dir = path.join(this.basePath, sessionId);
      await fs.mkdir(dir, { recursive: true });

      const key = `${sessionId}/${identifier}.png`;
      const filePath = path.join(this.basePath, key);

      let buffer: Buffer;
      if (typeof data === "string") {
        const cleanBase64 = data.replace(/^data:image\/\w+;base64,/, "");
        buffer = Buffer.from(cleanBase64, "base64");
      } else {
        buffer = data;
      }

      await fs.writeFile(filePath, buffer);

      return { success: true, url: `file://${filePath}`, key };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  async getScreenshot(key: string): Promise<Buffer | null> {
    const fs = await import("fs/promises");
    const path = await import("path");

    try {
      const filePath = path.join(this.basePath, key);
      return await fs.readFile(filePath);
    } catch {
      return null;
    }
  }

  async generateSignedUrl(key: string): Promise<string> {
    const path = await import("path");
    const filePath = path.join(this.basePath, key);
    return `file://${filePath}`;
  }

  async healthCheck(): Promise<{ healthy: boolean; error?: string }> {
    const fs = await import("fs/promises");
    try {
      await fs.access(this.basePath);
      return { healthy: true };
    } catch {
      // Try to create directory
      try {
        await fs.mkdir(this.basePath, { recursive: true });
        return { healthy: true };
      } catch (error) {
        return {
          healthy: false,
          error: error instanceof Error ? error.message : "Unknown error",
        };
      }
    }
  }
}

export function createStorageAdapter(config: Config): StorageAdapter {
  if (config.STORAGE_PROVIDER === "local") {
    return new LocalStorageAdapter();
  }
  return new MinIOStorageAdapter(config);
}
