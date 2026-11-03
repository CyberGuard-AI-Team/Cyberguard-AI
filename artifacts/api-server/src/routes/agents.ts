import { Router, type IRouter, type Request, type Response, type NextFunction } from "express";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { and, desc, eq, isNull } from "drizzle-orm";
import { z } from "zod/v4";
import { db, endpointDevicesTable, monitoringAgentsTable, securityEventsTable } from "@workspace/db";
import { detectBruteForceIndicators } from "../lib/cyberguard-analysis";
import { ownerIdFrom, requireAuth } from "../middlewares/requireAuth";

const router: IRouter = Router();
const agentApi: IRouter = Router();
const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const requestBuckets = new Map<string, { startedAt: number; count: number }>();
const auth = async (req: Request, res: Response, next: NextFunction) => {
  const token = req.header("authorization")?.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!token) { res.status(401).json({ error: "Agent bearer token required." }); return; }
  const [agent] = await db.select().from(monitoringAgentsTable).where(and(eq(monitoringAgentsTable.tokenHash, hash(token)), isNull(monitoringAgentsTable.revokedAt))).limit(1);
  if (!agent) { res.status(401).json({ error: "Invalid or revoked agent token." }); return; }
  res.locals.agent = agent;
  next();
};

router.post("/agents/enroll", requireAuth, async (req, res) => {
  const body = z.object({ name: z.string().min(1).max(120), operatingSystem: z.string().min(1).max(80), version: z.string().max(40).default("1.0.0") }).safeParse(req.body);
  if (!body.success) { res.status(400).json({ error: body.error.message }); return; }
  const ownerId = ownerIdFrom(req), id = randomUUID(), deviceId = randomUUID(), token = randomBytes(32).toString("base64url");
  await db.insert(endpointDevicesTable).values({ id: deviceId, ownerId, name: body.data.name, operatingSystem: body.data.operatingSystem, connectionStatus: "offline", lastSeen: null, agentVersion: body.data.version, simulated: false });
  await db.insert(monitoringAgentsTable).values({ id, ownerId, deviceId, tokenHash: hash(token), os: body.data.operatingSystem, version: body.data.version, status: "offline", config: { intervalSeconds: 15, enabled: true } });
  const apiBaseUrl = process.env.CYBERGUARD_PUBLIC_API_URL?.replace(/\/+$/, "") || `${req.protocol}://${req.get("host")}/api`;
  res.status(201).json({ agentId: id, deviceId, token, apiBaseUrl });
});

router.get("/agents", requireAuth, async (req, res) => {
  const agents = await db.select().from(monitoringAgentsTable).where(eq(monitoringAgentsTable.ownerId, ownerIdFrom(req))).orderBy(desc(monitoringAgentsTable.createdAt));
  res.json(agents.map(({ tokenHash: _secret, ...agent }) => agent));
});
router.patch("/agents/:id/config", requireAuth, async (req, res) => {
  const body = z.object({ enabled: z.boolean().optional(), intervalSeconds: z.number().int().min(5).max(3600).optional(), sources: z.array(z.string().max(80)).max(20).optional() }).strict().safeParse(req.body);
  if (!body.success) { res.status(400).json({ error: body.error.message }); return; }
  const ownerId = ownerIdFrom(req);
  const [agent] = await db.select().from(monitoringAgentsTable).where(and(eq(monitoringAgentsTable.id, req.params.id!), eq(monitoringAgentsTable.ownerId, ownerId), isNull(monitoringAgentsTable.revokedAt))).limit(1);
  if (!agent) { res.status(404).json({ error: "Agent not found." }); return; }
  const config = { ...agent.config, ...body.data };
  await db.update(monitoringAgentsTable).set({ config }).where(eq(monitoringAgentsTable.id, agent.id));
  res.json({ agentId: agent.id, config });
});
router.post("/agents/:id/revoke", requireAuth, async (req, res) => {
  const [agent] = await db.update(monitoringAgentsTable).set({ revokedAt: new Date(), status: "offline" }).where(and(eq(monitoringAgentsTable.id, req.params.id!), eq(monitoringAgentsTable.ownerId, ownerIdFrom(req)))).returning();
  if (!agent) { res.status(404).json({ error: "Agent not found." }); return; }
  await db.update(endpointDevicesTable).set({ connectionStatus: "offline" }).where(eq(endpointDevicesTable.id, agent.deviceId));
  res.json({ revoked: true });
});

agentApi.use(auth);
agentApi.use((_req, res, next) => {
  const agent = res.locals.agent as typeof monitoringAgentsTable.$inferSelect;
  const now = Date.now(), current = requestBuckets.get(agent.id);
  const bucket = !current || now - current.startedAt >= 60_000 ? { startedAt: now, count: 0 } : current;
  bucket.count += 1; requestBuckets.set(agent.id, bucket);
  if (bucket.count > 120) { res.status(429).json({ error: "Agent request limit exceeded; retry after one minute." }); return; }
  next();
});
agentApi.post("/heartbeat", async (_req, res) => {
  const agent = res.locals.agent as typeof monitoringAgentsTable.$inferSelect, now = new Date();
  await db.update(monitoringAgentsTable).set({ status: "online", lastHeartbeat: now }).where(eq(monitoringAgentsTable.id, agent.id));
  await db.update(endpointDevicesTable).set({ connectionStatus: "online", lastSeen: now }).where(eq(endpointDevicesTable.id, agent.deviceId));
  res.json({ status: "online", serverTime: now.toISOString(), config: agent.config });
});
agentApi.get("/status", async (_req, res) => {
  const agent = res.locals.agent as typeof monitoringAgentsTable.$inferSelect;
  res.json({ agentId: agent.id, status: agent.status, lastHeartbeat: agent.lastHeartbeat?.toISOString() ?? null, config: agent.config });
});
agentApi.patch("/config", async (req, res) => {
  const body = z.object({ enabled: z.boolean().optional(), intervalSeconds: z.number().int().min(5).max(3600).optional(), sources: z.array(z.string().max(80)).max(20).optional() }).strict().safeParse(req.body);
  if (!body.success) { res.status(400).json({ error: body.error.message }); return; }
  const agent = res.locals.agent as typeof monitoringAgentsTable.$inferSelect;
  const config = { ...agent.config, ...body.data };
  await db.update(monitoringAgentsTable).set({ config }).where(eq(monitoringAgentsTable.id, agent.id));
  res.json({ config });
});
agentApi.post("/disconnect", async (_req, res) => {
  const agent = res.locals.agent as typeof monitoringAgentsTable.$inferSelect;
  await db.update(monitoringAgentsTable).set({ status: "offline" }).where(eq(monitoringAgentsTable.id, agent.id));
  await db.update(endpointDevicesTable).set({ connectionStatus: "offline" }).where(eq(endpointDevicesTable.id, agent.deviceId));
  res.json({ status: "offline" });
});
agentApi.post("/events", async (req, res) => {
  const payload = z.object({ events: z.array(z.object({ timestamp: z.coerce.date(), eventId: z.string().max(80), eventType: z.string().max(120), user: z.string().max(120).default("unknown"), sourceIp: z.string().max(64).default(""), destinationIp: z.string().max(64).nullable().optional(), severity: z.enum(["Critical", "High", "Medium", "Low", "Informational"]), status: z.string().max(80), description: z.string().max(2000), source: z.string().max(120), metadata: z.record(z.string(), z.unknown()).optional(), checkpoint: z.string().max(500).optional() }).strict()).min(1).max(500) }).safeParse(req.body);
  if (!payload.success) { res.status(400).json({ error: payload.error.message }); return; }
  const agent = res.locals.agent as typeof monitoringAgentsTable.$inferSelect;
  const values = payload.data.events.map((event) => {
    const id = `event_${hash(`${agent.id}:${event.source}:${event.eventId}:${event.timestamp.toISOString()}:${event.metadata?.recordId ?? event.metadata?.cursor ?? event.description}`).slice(0,32)}`;
    return { id, ownerId: agent.ownerId, agentId: agent.id, eventSource: event.source, metadata: event.metadata ?? {}, timestamp: event.timestamp, eventId: event.eventId, eventType: event.eventType, user: event.user, sourceIp: event.sourceIp, destinationIp: event.destinationIp ?? null, severity: event.severity, status: event.status, description: event.description, simulated: false, anomalyScore: null };
  });
  const inserted = await db.insert(securityEventsTable).values(values).onConflictDoNothing().returning({ id: securityEventsTable.id });
  await detectBruteForceIndicators(agent.ownerId);
  const now = new Date();
  await db.update(monitoringAgentsTable).set({ lastHeartbeat: now, status: "online" }).where(eq(monitoringAgentsTable.id, agent.id));
  await db.update(endpointDevicesTable).set({ connectionStatus: "online", lastSeen: now }).where(eq(endpointDevicesTable.id, agent.deviceId));
  res.json({ accepted: inserted.length, duplicates: values.length - inserted.length });
});

router.use("/agent", agentApi);
export default router;
