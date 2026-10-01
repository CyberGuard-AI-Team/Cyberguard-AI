import { createHash } from "node:crypto";
import { and, desc, eq, inArray } from "drizzle-orm";
import {
  db,
  securityEventsTable,
  threatFindingsTable,
  type SecurityEvent,
  type ThreatFinding,
} from "@workspace/db";
import { makeDemoEvents } from "./cyberguard-demo";

const seedJobs = new Map<string, Promise<void>>();

export function toSecurityEvent(row: SecurityEvent) {
  return {
    id: row.id,
    timestamp: row.timestamp.toISOString(),
    eventId: row.eventId,
    eventType: row.eventType,
    user: row.user,
    sourceIp: row.sourceIp,
    destinationIp: row.destinationIp,
    severity: row.severity as
      | "Critical"
      | "High"
      | "Medium"
      | "Low"
      | "Informational",
    status: row.status,
    description: row.description,
    simulated: row.simulated,
    anomalyScore: row.anomalyScore,
  };
}

export function toThreatFinding(row: ThreatFinding) {
  return {
    id: row.id,
    timestamp: row.timestamp.toISOString(),
    title: row.title,
    category: row.category,
    severity: row.severity as
      | "Critical"
      | "High"
      | "Medium"
      | "Low"
      | "Informational",
    source: row.source,
    evidence: row.evidence,
    confidence: row.confidence,
    status: row.status as
      | "New"
      | "Investigating"
      | "Resolved"
      | "Dismissed",
    eventIds: row.eventIds,
    simulated: row.simulated,
  };
}

export async function ensureDemoData(ownerId: string): Promise<void> {
  const current = seedJobs.get(ownerId);
  if (current) {
    await current;
    return;
  }

  const job = seedDemoData(ownerId);
  seedJobs.set(ownerId, job);
  try {
    await job;
  } finally {
    seedJobs.delete(ownerId);
  }
}

async function seedDemoData(ownerId: string): Promise<void> {
  const [sample] = await db
    .select({ id: securityEventsTable.id })
    .from(securityEventsTable)
    .where(
      and(
        eq(securityEventsTable.ownerId, ownerId),
        eq(securityEventsTable.simulated, true),
      ),
    )
    .limit(1);
  if (sample) {
    return;
  }

  await db.insert(securityEventsTable).values(makeDemoEvents(ownerId));
  await detectBruteForceIndicators(ownerId);
}

export async function detectBruteForceIndicators(
  ownerId: string,
): Promise<number> {
  const events = await db
    .select()
    .from(securityEventsTable)
    .where(eq(securityEventsTable.ownerId, ownerId))
    .orderBy(desc(securityEventsTable.timestamp))
    .limit(10_000);

  const groups = new Map<string, SecurityEvent[]>();
  for (const event of events) {
    if (event.eventType !== "Failed Login") continue;
    const group = groups.get(event.sourceIp) ?? [];
    group.push(event);
    groups.set(event.sourceIp, group);
  }

  let created = 0;
  for (const [sourceIp, failed] of groups) {
    failed.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
    let burst: SecurityEvent[] | null = null;
    for (let start = 0; start < failed.length; start += 1) {
      const first = failed[start]!;
      const window = failed.filter(
        (event) =>
          event.timestamp.getTime() >= first.timestamp.getTime() &&
          event.timestamp.getTime() <= first.timestamp.getTime() + 15 * 60_000,
      );
      if (window.length >= 5) {
        burst = window;
        break;
      }
    }
    if (!burst) continue;

    const firstAt = burst[0]!.timestamp.getTime();
    const lastAt = burst[burst.length - 1]!.timestamp.getTime();
    const followup = events.filter(
      (event) =>
        event.sourceIp === sourceIp &&
        event.timestamp.getTime() >= lastAt &&
        event.timestamp.getTime() <= lastAt + 60 * 60_000 &&
        (event.eventType === "Successful Login" ||
          event.eventType === "Privilege Change"),
    );
    const evidenceEvents = [...burst, ...followup];
    const eventIds = [...new Set(evidenceEvents.map((event) => event.id))];
    const roundedWindow = Math.floor(firstAt / (15 * 60_000));
    const id = `threat_${createHash("sha256")
      .update(`${ownerId}:${sourceIp}:${roundedWindow}`)
      .digest("hex")
      .slice(0, 18)}`;
    const succeeded = followup.some(
      (event) => event.eventType === "Successful Login",
    );
    const privileged = followup.some(
      (event) => event.eventType === "Privilege Change",
    );
    const simulated = evidenceEvents.every((event) => event.simulated);
    const source = simulated ? "SIMULATED DATA · Endpoint simulator" : "Uploaded logs";
    const evidence = `${burst.length} failed sign-in events from ${sourceIp} occurred within 15 minutes${succeeded ? ", followed by a successful sign-in" : ""}${privileged ? " and privileged activity" : ""}. This is a rule-based investigation indicator, not proof of compromise.`;

    const inserted = await db
      .insert(threatFindingsTable)
      .values({
        id,
        ownerId,
        timestamp: new Date(lastAt),
        title: succeeded
          ? "Failed sign-in burst followed by a successful login"
          : "High-volume failed sign-in burst",
        category: "Brute-force-like activity",
        severity: succeeded && privileged ? "High" : "Medium",
        source,
        evidence,
        confidence: null,
        status: "New",
        eventIds,
        simulated,
      })
      .onConflictDoNothing()
      .returning({ id: threatFindingsTable.id });
    if (inserted.length > 0) created += 1;
  }
  return created;
}

export async function regenerateDemoData(ownerId: string): Promise<number> {
  const simulatedEvents = await db
    .select({ id: securityEventsTable.id })
    .from(securityEventsTable)
    .where(
      and(
        eq(securityEventsTable.ownerId, ownerId),
        eq(securityEventsTable.simulated, true),
      ),
    );
  const simulatedIds = new Set(simulatedEvents.map((event) => event.id));
  const findings = await db
    .select({ id: threatFindingsTable.id, eventIds: threatFindingsTable.eventIds })
    .from(threatFindingsTable)
    .where(eq(threatFindingsTable.ownerId, ownerId));
  const staleFindingIds = findings
    .filter(
      (finding) => finding.eventIds.some((id) => simulatedIds.has(id)),
    )
    .map((finding) => finding.id);
  if (staleFindingIds.length > 0) {
    await db
      .delete(threatFindingsTable)
      .where(
        and(
          eq(threatFindingsTable.ownerId, ownerId),
          inArray(threatFindingsTable.id, staleFindingIds),
        ),
      );
  }
  await db
    .delete(threatFindingsTable)
    .where(
      and(
        eq(threatFindingsTable.ownerId, ownerId),
        eq(threatFindingsTable.simulated, true),
      ),
    );
  await db
    .delete(securityEventsTable)
    .where(
      and(
        eq(securityEventsTable.ownerId, ownerId),
        eq(securityEventsTable.simulated, true),
      ),
    );

  const generated = makeDemoEvents(ownerId);
  await db.insert(securityEventsTable).values(generated);
  await detectBruteForceIndicators(ownerId);
  return generated.length;
}

export async function createEventRows(
  ownerId: string,
  rows: Array<{
    timestamp: Date | string;
    eventId: string;
    eventType: string;
    user: string;
    sourceIp: string;
    destinationIp?: string | null;
    severity: string;
    status: string;
    description: string;
    simulated?: boolean;
  }>,
): Promise<number> {
  if (rows.length === 0) return 0;
  const values = rows.map((row) => {
    const timestamp =
      row.timestamp instanceof Date ? row.timestamp : new Date(row.timestamp);
    const dedupeKey = JSON.stringify([
      ownerId,
      timestamp.toISOString(),
      row.eventId,
      row.eventType,
      row.user,
      row.sourceIp,
    ]);
    return {
      id: `event_${createHash("sha256").update(dedupeKey).digest("hex").slice(0, 32)}`,
      ownerId,
      timestamp,
      eventId: row.eventId,
      eventType: row.eventType,
      user: row.user,
      sourceIp: row.sourceIp,
      destinationIp: row.destinationIp ?? null,
      severity: row.severity,
      status: row.status,
      description: row.description,
      simulated: row.simulated ?? false,
      anomalyScore: null,
    };
  });
  const inserted = await db
    .insert(securityEventsTable)
    .values(values)
    .onConflictDoNothing()
    .returning({ id: securityEventsTable.id });
  await detectBruteForceIndicators(ownerId);
  return inserted.length;
}