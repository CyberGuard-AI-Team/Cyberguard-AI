import { getAuth } from "@clerk/express";
import type { Request, RequestHandler } from "express";

export const requireAuth: RequestHandler = (req, res, next) => {
  if (!getAuth(req).userId) {
    res.status(401).json({ error: "Sign in to access this security workspace." });
    return;
  }
  next();
};

export function ownerIdFrom(req: Request): string {
  const userId = getAuth(req).userId;
  if (!userId) {
    throw new Error("Authenticated request is missing its Clerk user ID.");
  }
  return userId;
}