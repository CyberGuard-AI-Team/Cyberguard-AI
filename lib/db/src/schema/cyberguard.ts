import { createInsertSchema } from "drizzle-zod";
import {
  boolean,
  index,
  integer,
  pgTable,
  real,
  text,
  timestamp,
} from "drizzle-orm/pg-core";
import { z } from "zod/v4";

export const securityEventsTable = pgTable(
  "security_events",
  {
    id: text("id").primaryKey(),
    ownerId: text("owner_id").notNull(),
    timestamp: timestamp("timestamp", { withTimezone: true }).notNull(),
    eventId: text("event_id").notNull(),
    eventType: text("event_type").notNull(),
    user: text("user").notNull(),
    sourceIp: text("source_ip").notNull(),
    destinationIp: text("destination_ip"),
    severity: text("severity").notNull(),
    status: text("status").notNull(),
    description: text("description").notNull(),
    simulated: boolean("simulated").notNull().default(false),
    anomalyScore: real("anomaly_score"),
  },
  (table) => [
    index("security_events_owner_timestamp_idx").on(table.ownerId, table.timestamp),
    index("security_events_severity_idx").on(table.severity),
    index("security_events_event_id_idx").on(table.eventId),
  ],
);

export const insertSecurityEventSchema = createInsertSchema(
  securityEventsTable,
).omit({ id: true });
export type InsertSecurityEvent = z.infer<typeof insertSecurityEventSchema>;
export type SecurityEvent = typeof securityEventsTable.$inferSelect;

export const threatFindingsTable = pgTable(
  "threat_findings",
  {
    id: text("id").primaryKey(),
    ownerId: text("owner_id").notNull(),
    timestamp: timestamp("timestamp", { withTimezone: true }).notNull(),
    title: text("title").notNull(),
    category: text("category").notNull(),
    severity: text("severity").notNull(),
    source: text("source").notNull(),
    evidence: text("evidence").notNull(),
    confidence: real("confidence"),
    status: text("status").notNull().default("New"),
    eventIds: text("event_ids").array().notNull().default([]),
    simulated: boolean("simulated").notNull().default(false),
  },
  (table) => [
    index("threat_findings_owner_timestamp_idx").on(table.ownerId, table.timestamp),
    index("threat_findings_severity_idx").on(table.severity),
    index("threat_findings_status_idx").on(table.status),
  ],
);

export const insertThreatFindingSchema = createInsertSchema(
  threatFindingsTable,
).omit({ id: true });
export type InsertThreatFinding = z.infer<typeof insertThreatFindingSchema>;
export type ThreatFinding = typeof threatFindingsTable.$inferSelect;

export const securityScansTable = pgTable(
  "security_scans",
  {
    id: text("id").primaryKey(),
    ownerId: text("owner_id").notNull(),
    type: text("type").notNull(),
    status: text("status").notNull(),
    progress: integer("progress").notNull().default(0),
    currentStage: text("current_stage").notNull(),
    startedAt: timestamp("started_at", { withTimezone: true }).notNull(),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    threats: integer("threats").notNull().default(0),
    anomalies: integer("anomalies").notNull().default(0),
    warnings: integer("warnings").notNull().default(0),
    informational: integer("informational").notNull().default(0),
    simulated: boolean("simulated").notNull().default(false),
    modelStatus: text("model_status").notNull(),
  },
  (table) => [
    index("security_scans_owner_started_at_idx").on(table.ownerId, table.startedAt),
    index("security_scans_status_idx").on(table.status),
  ],
);

export const insertSecurityScanSchema = createInsertSchema(
  securityScansTable,
).omit({ id: true });
export type InsertSecurityScan = z.infer<typeof insertSecurityScanSchema>;
export type SecurityScan = typeof securityScansTable.$inferSelect;

export const endpointDevicesTable = pgTable(
  "endpoint_devices",
  {
    id: text("id").primaryKey(),
    ownerId: text("owner_id").notNull(),
    name: text("name").notNull(),
    operatingSystem: text("operating_system").notNull(),
    connectionStatus: text("connection_status").notNull(),
    lastSeen: timestamp("last_seen", { withTimezone: true }),
    agentVersion: text("agent_version"),
    simulated: boolean("simulated").notNull().default(false),
  },
  (table) => [
    index("endpoint_devices_owner_status_idx").on(table.ownerId, table.connectionStatus),
    index("endpoint_devices_last_seen_idx").on(table.lastSeen),
  ],
);

export const insertEndpointDeviceSchema = createInsertSchema(
  endpointDevicesTable,
).omit({ id: true });
export type InsertEndpointDevice = z.infer<typeof insertEndpointDeviceSchema>;
export type EndpointDevice = typeof endpointDevicesTable.$inferSelect;