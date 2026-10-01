import { Router, type IRouter } from "express";
import { randomUUID } from "node:crypto";
import { and, count, desc, eq, inArray } from "drizzle-orm";
import {
  AskCyberguardAssistantBody,
  AskCyberguardAssistantResponse,
  GetCyberguardAnalyticsResponse,
  GetCyberguardDevicesResponse,
  GetCyberguardEventsQueryParams,
  GetCyberguardEventsResponse,
  GetCyberguardOverviewResponse,
  GetCyberguardScanParams,
  GetCyberguardScanResponse,
  GetCyberguardScansResponse,
  GetCyberguardThreatsResponse,
  ResetCyberguardDemoResponse,
  StartCyberguardScanBody,
  StartCyberguardScanResponse,
  UpdateCyberguardThreatBody,
  UpdateCyberguardThreatParams,
  UpdateCyberguardThreatResponse,
  UploadCyberguardEventsBody,
  UploadCyberguardEventsResponse,
} from "@workspace/api-zod";
import {
  db,
  endpointDevicesTable,
  securityEventsTable,
  securityScansTable,
  threatFindingsTable,
  type SecurityScan,
} from "@workspace/db";
import { logger } from "../lib/logger";
import {
  createEventRows,
  detectBruteForceIndicators,
  ensureDemoData,
  regenerateDemoData,
  toSecurityEvent,
  toThreatFinding,
} from "../lib/cyberguard-analysis";
import { ownerIdFrom, requireAuth } from "../middlewares/requireAuth";

const router: IRouter = Router();
router.use(requireAuth);

function toScan(row: SecurityScan) {
  return {
    id: row.id,
    type: row.type as "quick" | "deep",
    status: row.status as "queued" | "running" | "completed" | "failed",
    progress: row.progress,
    currentStage: row.currentStage,
    startedAt: row.startedAt.toISOString(),
    completedAt: row.completedAt?.toISOString() ?? null,
    threats: row.threats,
    anomalies: row.anomalies,
    warnings: row.warnings,
    informational: row.informational,
    simulated: row.simulated,
    modelStatus: row.modelStatus,
  };
}

router.get("/cyberguard/overview", async (req, res): Promise<void> => {
  const ownerId = ownerIdFrom(req);
  await ensureDemoData(ownerId);
  const [eventTotal] = await db
    .select({ value: count() })
    .from(securityEventsTable)
    .where(eq(securityEventsTable.ownerId, ownerId));
  const [simulatedEventTotal] = await db
    .select({ value: count() })
    .from(securityEventsTable)
    .where(
      and(
        eq(securityEventsTable.ownerId, ownerId),
        eq(securityEventsTable.simulated, true),
      ),
    );
  const [activeTotal] = await db
    .select({ value: count() })
    .from(threatFindingsTable)
    .where(
      and(
        eq(threatFindingsTable.ownerId, ownerId),
        inArray(threatFindingsTable.status, ["New", "Investigating"]),
      ),
    );
  const events = await db
    .select()
    .from(securityEventsTable)
    .where(eq(securityEventsTable.ownerId, ownerId))
    .orderBy(desc(securityEventsTable.timestamp))
    .limit(250);
  const threats = await db
    .select()
    .from(threatFindingsTable)
    .where(eq(threatFindingsTable.ownerId, ownerId))
    .orderBy(desc(threatFindingsTable.timestamp))
    .limit(100);
  const active = threats.filter(
    (threat) => threat.status === "New" || threat.status === "Investigating",
  );
  const suspiciousEventIds = new Set(active.flatMap((threat) => threat.eventIds));
  const now = new Date();
  const startOfToday = new Date(now);
  startOfToday.setHours(0, 0, 0, 0);
  const today = events.filter((event) => event.timestamp >= startOfToday);
  const devices = await db
    .select({ id: endpointDevicesTable.id })
    .from(endpointDevicesTable)
    .where(eq(endpointDevicesTable.ownerId, ownerId))
    .limit(1);
  const [lastScan] = await db
    .select({ startedAt: securityScansTable.startedAt })
    .from(securityScansTable)
    .where(eq(securityScansTable.ownerId, ownerId))
    .orderBy(desc(securityScansTable.startedAt))
    .limit(1);
  const simulated =
    Number(eventTotal?.value ?? 0) > 0 &&
    Number(eventTotal?.value ?? 0) === Number(simulatedEventTotal?.value ?? 0);
  const response = GetCyberguardOverviewResponse.parse({
    totalEvents: Number(eventTotal?.value ?? 0),
    activeThreats: Number(activeTotal?.value ?? 0),
    anomaliesToday: new Set(
      today
        .filter((event) => suspiciousEventIds.has(event.id))
        .map((event) => event.id),
    ).size,
    failedLogins: today.filter((event) => event.eventType === "Failed Login")
      .length,
    criticalEvents: today.filter((event) => event.severity === "Critical").length,
    deviceStatus: devices.length === 0 ? "No live device connected" : "Device connected",
    modelStatus: "Not trained — ML/DL results are unavailable",
    lastScan: lastScan?.startedAt.toISOString() ?? null,
    recentEvents: events.slice(0, 7).map(toSecurityEvent),
    recentThreats: threats.slice(0, 4).map(toThreatFinding),
    simulated,
  });
  res.json(response);
});

router.get("/cyberguard/events", async (req, res): Promise<void> => {
  const ownerId = ownerIdFrom(req);
  const parsed = GetCyberguardEventsQueryParams.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  await ensureDemoData(ownerId);
  const rows = await db
    .select()
    .from(securityEventsTable)
    .where(eq(securityEventsTable.ownerId, ownerId))
    .orderBy(desc(securityEventsTable.timestamp))
    .limit(10_000);
  const search = parsed.data.search?.trim().toLocaleLowerCase();
  const filtered = rows.filter((event) => {
    if (parsed.data.severity && event.severity !== parsed.data.severity) {
      return false;
    }
    if (!search) return true;
    return [
      event.id,
      event.eventId,
      event.eventType,
      event.user,
      event.sourceIp,
      event.destinationIp ?? "",
      event.status,
      event.description,
    ].some((value) => value.toLocaleLowerCase().includes(search));
  });
  res.json(
    GetCyberguardEventsResponse.parse(
      filtered.slice(0, parsed.data.limit).map(toSecurityEvent),
    ),
  );
});

router.post("/cyberguard/events/upload", async (req, res): Promise<void> => {
  const ownerId = ownerIdFrom(req);
  const parsed = UploadCyberguardEventsBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const invalidDate = parsed.data.events.find(
    (event) => Number.isNaN(new Date(event.timestamp).getTime()),
  );
  if (invalidDate) {
    res.status(400).json({ error: "Each event must have a valid timestamp." });
    return;
  }
  await ensureDemoData(ownerId);
  const accepted = await createEventRows(ownerId, parsed.data.events);
  const rejected = parsed.data.events.length - accepted;
  const simulated = parsed.data.events.every((event) => event.simulated === true);
  res.status(201).json(
    UploadCyberguardEventsResponse.parse({
      accepted,
      rejected,
      simulated,
      message: `${accepted} uploaded event${accepted === 1 ? "" : "s"} stored and analyzed; ${rejected} duplicate record${rejected === 1 ? "" : "s"} skipped. Uploaded records are not live-device telemetry.`,
    }),
  );
});

router.get("/cyberguard/threats", async (req, res): Promise<void> => {
  const ownerId = ownerIdFrom(req);
  await ensureDemoData(ownerId);
  const rows = await db
    .select()
    .from(threatFindingsTable)
    .where(eq(threatFindingsTable.ownerId, ownerId))
    .orderBy(desc(threatFindingsTable.timestamp))
    .limit(1000);
  res.json(GetCyberguardThreatsResponse.parse(rows.map(toThreatFinding)));
});

router.patch("/cyberguard/threats/:threatId", async (req, res): Promise<void> => {
  const ownerId = ownerIdFrom(req);
  const params = UpdateCyberguardThreatParams.safeParse(req.params);
  const body = UpdateCyberguardThreatBody.safeParse(req.body);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  if (!body.success) {
    res.status(400).json({ error: body.error.message });
    return;
  }
  const [updated] = await db
    .update(threatFindingsTable)
    .set({ status: body.data.status })
    .where(
      and(
        eq(threatFindingsTable.id, params.data.threatId),
        eq(threatFindingsTable.ownerId, ownerId),
      ),
    )
    .returning();
  if (!updated) {
    res.status(404).json({ error: "Threat finding not found." });
    return;
  }
  res.json(UpdateCyberguardThreatResponse.parse(toThreatFinding(updated)));
});

router.get("/cyberguard/scans", async (req, res): Promise<void> => {
  const ownerId = ownerIdFrom(req);
  await ensureDemoData(ownerId);
  const rows = await db
    .select()
    .from(securityScansTable)
    .where(eq(securityScansTable.ownerId, ownerId))
    .orderBy(desc(securityScansTable.startedAt))
    .limit(100);
  res.json(GetCyberguardScansResponse.parse(rows.map(toScan)));
});

router.post("/cyberguard/scans", async (req, res): Promise<void> => {
  const ownerId = ownerIdFrom(req);
  const parsed = StartCyberguardScanBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  await ensureDemoData(ownerId);
  const events = await db
    .select({ simulated: securityEventsTable.simulated })
    .from(securityEventsTable)
    .where(eq(securityEventsTable.ownerId, ownerId))
    .limit(10_000);
  const id = randomId();
  const [scan] = await db
    .insert(securityScansTable)
    .values({
      id,
      ownerId,
      type: parsed.data.type,
      status: "queued",
      progress: 0,
      currentStage: "Queued",
      startedAt: new Date(),
      completedAt: null,
      threats: 0,
      anomalies: 0,
      warnings: 0,
      informational: 0,
      simulated: events.length > 0 && events.every((event) => event.simulated),
      modelStatus: "Not trained — ML/DL signals excluded; rule-based checks only",
    })
    .returning();
  if (!scan) {
    res.status(500).json({ error: "Unable to start the scan." });
    return;
  }
  void runScan(id, ownerId, parsed.data.type).catch(async (error: unknown) => {
    logger.error({ error, scanId: id }, "CyberGuard scan failed");
    await db
      .update(securityScansTable)
      .set({
        status: "failed",
        currentStage: "Scan failed — see server logs",
        completedAt: new Date(),
      })
      .where(
        and(
          eq(securityScansTable.id, id),
          eq(securityScansTable.ownerId, ownerId),
        ),
      );
  });
  res.status(202).json(StartCyberguardScanResponse.parse(toScan(scan)));
});

router.get("/cyberguard/scans/:scanId", async (req, res): Promise<void> => {
  const ownerId = ownerIdFrom(req);
  const params = GetCyberguardScanParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }
  const [scan] = await db
    .select()
    .from(securityScansTable)
    .where(
      and(
        eq(securityScansTable.id, params.data.scanId),
        eq(securityScansTable.ownerId, ownerId),
      ),
    )
    .limit(1);
  if (!scan) {
    res.status(404).json({ error: "Scan not found." });
    return;
  }
  res.json(GetCyberguardScanResponse.parse(toScan(scan)));
});

router.get("/cyberguard/devices", async (req, res): Promise<void> => {
  const ownerId = ownerIdFrom(req);
  const rows = await db
    .select()
    .from(endpointDevicesTable)
    .where(eq(endpointDevicesTable.ownerId, ownerId))
    .orderBy(desc(endpointDevicesTable.lastSeen))
    .limit(100);
  res.json(
    GetCyberguardDevicesResponse.parse(
      rows.map((row) => ({
        id: row.id,
        name: row.name,
        operatingSystem: row.operatingSystem,
        connectionStatus: row.connectionStatus as
          | "online"
          | "recently_seen"
          | "offline",
        lastSeen: row.lastSeen?.toISOString() ?? null,
        agentVersion: row.agentVersion,
        simulated: row.simulated,
      })),
    ),
  );
});

router.get("/cyberguard/analytics", async (req, res): Promise<void> => {
  const ownerId = ownerIdFrom(req);
  await ensureDemoData(ownerId);
  const rows = await db
    .select()
    .from(securityEventsTable)
    .where(eq(securityEventsTable.ownerId, ownerId))
    .orderBy(desc(securityEventsTable.timestamp))
    .limit(10_000);
  const currentHour = new Date();
  currentHour.setUTCMinutes(0, 0, 0);
  const eventsByHour = Array.from({ length: 24 }, (_, offset) => {
    const start = new Date(currentHour.getTime() - (23 - offset) * 60 * 60_000);
    const end = new Date(start.getTime() + 60 * 60_000);
    const bucket = rows.filter(
      (event) => event.timestamp >= start && event.timestamp < end,
    );
    return {
      hour: start.toISOString().slice(11, 16),
      count: bucket.length,
      anomalies: bucket.filter((event) =>
        ["High", "Critical"].includes(event.severity),
      ).length,
    };
  });
  const severityCounts = ["Critical", "High", "Medium", "Low", "Informational"].map(
    (severity) => ({
      severity,
      count: rows.filter((event) => event.severity === severity).length,
    }),
  );
  const byType = new Map<string, number>();
  for (const row of rows) byType.set(row.eventType, (byType.get(row.eventType) ?? 0) + 1);
  const eventTypeCounts = [...byType.entries()]
    .map(([eventType, value]) => ({ eventType, count: value }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);
  const simulated = rows.length > 0 && rows.every((event) => event.simulated);
  res.json(
    GetCyberguardAnalyticsResponse.parse({
      eventsByHour,
      severityCounts,
      eventTypeCounts,
      simulated,
    }),
  );
});

router.post("/cyberguard/assistant/chat", async (req, res): Promise<void> => {
  const ownerId = ownerIdFrom(req);
  const parsed = AskCyberguardAssistantBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  await ensureDemoData(ownerId);
  const question = parsed.data.question.trim();
  const [events, threats] = await Promise.all([
    db
      .select()
      .from(securityEventsTable)
      .where(eq(securityEventsTable.ownerId, ownerId))
      .orderBy(desc(securityEventsTable.timestamp))
      .limit(10_000),
    db
      .select()
      .from(threatFindingsTable)
      .where(eq(threatFindingsTable.ownerId, ownerId))
      .orderBy(desc(threatFindingsTable.timestamp))
      .limit(1000),
  ]);
  const eventIdQuery = question.match(/\b\d{4,}\b/)?.[0];
  const ipQuery = question.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0];
  let relevantEvents: typeof events = [];
  let relevantThreats: typeof threats = [];
  if (eventIdQuery) {
    relevantEvents = events.filter((event) => event.eventId === eventIdQuery);
  } else if (ipQuery) {
    relevantEvents = events.filter(
      (event) =>
        event.sourceIp === ipQuery || event.destinationIp === ipQuery,
    );
    relevantThreats = threats.filter((threat) =>
      threat.evidence.includes(ipQuery),
    );
  } else if (/login|sign.?in|failed|brute|credential/i.test(question)) {
    relevantEvents = events.filter((event) =>
      /login|sign.?in/i.test(event.eventType),
    );
    relevantThreats = threats.filter((threat) =>
      /authentication|brute.?force/i.test(threat.category),
    );
  } else if (/today|happened|summary|recent/i.test(question)) {
    const since = Date.now() - 24 * 60 * 60_000;
    relevantEvents = events.filter(
      (event) => event.timestamp.getTime() >= since,
    );
    relevantThreats = threats.filter(
      (threat) => threat.timestamp.getTime() >= since,
    );
  } else {
    relevantThreats = threats.filter(
      (threat) => threat.status === "New" || threat.status === "Investigating",
    );
    const ids = new Set(relevantThreats.flatMap((threat) => threat.eventIds));
    relevantEvents = events.filter((event) => ids.has(event.id));
  }

  const evidenceIds = [
    ...new Set(relevantEvents.slice(0, 8).map((event) => event.id)),
  ];
  const evidenceAvailable = evidenceIds.length > 0;
  let answer = "I don't have enough evidence from the collected telemetry to determine that.";
  if (evidenceAvailable && relevantThreats.length > 0) {
    const finding = relevantThreats[0]!;
    answer = `${finding.title}. ${finding.evidence} Finding ID: ${finding.id}.`;
  } else if (evidenceAvailable && relevantEvents.length > 0) {
    const failed = relevantEvents.filter(
      (event) => event.eventType === "Failed Login",
    );
    const simulated = relevantEvents.every((event) => event.simulated);
    answer = `${relevantEvents.length} matching event${relevantEvents.length === 1 ? "" : "s"} found${simulated ? " in simulated telemetry" : " in uploaded telemetry"}. ${failed.length > 0 ? `${failed.length} are failed sign-in events. ` : ""}Example event records: ${relevantEvents.slice(0, 4).map((event) => `${event.eventId} (${event.id})`).join(", ")}.`;
  }
  const simulated =
    evidenceAvailable &&
    relevantEvents.length > 0 &&
    relevantEvents.every((event) => event.simulated);
  res.json(
    AskCyberguardAssistantResponse.parse({
      answer,
      evidenceIds: evidenceIds.slice(0, 10),
      evidenceAvailable,
      simulated,
    }),
  );
});

router.post("/cyberguard/demo/reset", async (req, res): Promise<void> => {
  const ownerId = ownerIdFrom(req);
  const accepted = await regenerateDemoData(ownerId);
  res.json(
    ResetCyberguardDemoResponse.parse({
      accepted,
      rejected: 0,
      simulated: true,
      message: `${accepted} simulated security events were regenerated. Uploaded logs were preserved.`,
    }),
  );
});

async function runScan(
  id: string,
  ownerId: string,
  type: "quick" | "deep",
): Promise<void> {
  const stages =
    type === "quick"
      ? [
          "Loading stored security events",
          "Reviewing authentication sequences",
          "Checking rule-based indicators",
        ]
      : [
          "Loading stored security events",
          "Reviewing authentication sequences",
          "Correlating process and network event metadata",
          "Evaluating rule-based indicators",
        ];
  const delayMs = type === "quick" ? 550 : 800;
  await db
    .update(securityScansTable)
    .set({ status: "running", currentStage: stages[0], progress: 12 })
    .where(
      and(
        eq(securityScansTable.id, id),
        eq(securityScansTable.ownerId, ownerId),
      ),
    );

  for (let index = 0; index < stages.length; index += 1) {
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    await db
      .update(securityScansTable)
      .set({
        status: "running",
        currentStage: stages[index]!,
        progress: Math.min(85, Math.round(((index + 1) / stages.length) * 85)),
      })
      .where(
        and(
          eq(securityScansTable.id, id),
          eq(securityScansTable.ownerId, ownerId),
        ),
      );
  }

  await detectBruteForceIndicators(ownerId);
  const [events, threats] = await Promise.all([
    db
      .select()
      .from(securityEventsTable)
      .where(eq(securityEventsTable.ownerId, ownerId))
      .limit(10_000),
    db
      .select()
      .from(threatFindingsTable)
      .where(eq(threatFindingsTable.ownerId, ownerId))
      .limit(1000),
  ]);
  const active = threats.filter(
    (threat) => threat.status === "New" || threat.status === "Investigating",
  );
  const suspiciousIds = new Set(active.flatMap((threat) => threat.eventIds));
  const [updated] = await db
    .update(securityScansTable)
    .set({
      status: "completed",
      progress: 100,
      currentStage: "Scan complete — rule-based indicators only",
      completedAt: new Date(),
      threats: active.length,
      anomalies: suspiciousIds.size,
      warnings: events.filter((event) => event.severity === "Medium").length,
      informational: events.filter(
        (event) =>
          event.severity === "Low" || event.severity === "Informational",
      ).length,
      simulated: events.length > 0 && events.every((event) => event.simulated),
      modelStatus: "Not trained — ML/DL signals excluded; rule-based checks only",
    })
    .where(
      and(
        eq(securityScansTable.id, id),
        eq(securityScansTable.ownerId, ownerId),
      ),
    )
    .returning({ id: securityScansTable.id });
  logger.info(
    { scanId: id, ownerId, completed: Boolean(updated), type },
    "CyberGuard scan processing finished",
  );
}

function randomId(): string {
  return `scan_${randomUUID()}`;
}

export default router;