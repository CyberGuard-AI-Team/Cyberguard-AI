import { randomUUID } from "node:crypto";

const normalEventTypes = [
  {
    eventId: "4624",
    eventType: "Successful Login",
    user: "j.wells",
    severity: "Low",
    status: "Success",
    description: "Interactive sign-in completed from a known private network.",
    sourceIp: "10.20.1.15",
  },
  {
    eventId: "4688",
    eventType: "Process Start",
    user: "SYSTEM",
    severity: "Informational",
    status: "Observed",
    description: "A signed operating-system service process started.",
    sourceIp: "127.0.0.1",
  },
  {
    eventId: "5156",
    eventType: "Network Connection",
    user: "SYSTEM",
    severity: "Informational",
    status: "Allowed",
    description: "An outbound connection was permitted by the local firewall.",
    sourceIp: "10.20.1.15",
  },
  {
    eventId: "4624",
    eventType: "Successful Login",
    user: "svc-backup",
    severity: "Low",
    status: "Success",
    description: "A scheduled service account sign-in completed.",
    sourceIp: "10.20.1.26",
  },
  {
    eventId: "5158",
    eventType: "Port Activity",
    user: "SYSTEM",
    severity: "Low",
    status: "Observed",
    description: "A local process bound to an ephemeral port.",
    sourceIp: "10.20.1.15",
  },
] as const;

export function makeDemoEvents(ownerId: string) {
  const now = Date.now();
  const normal = Array.from({ length: 38 }, (_, index) => {
    const template = normalEventTypes[index % normalEventTypes.length]!;
    const minutesAgo = 28 + index * 34;
    return {
      ownerId,
      timestamp: new Date(now - minutesAgo * 60_000),
      eventId: template.eventId,
      eventType: template.eventType,
      user: template.user,
      sourceIp: template.sourceIp,
      destinationIp:
        template.eventType === "Network Connection"
          ? "192.0.2.40"
          : null,
      severity: template.severity,
      status: template.status,
      description: template.description,
      simulated: true,
      anomalyScore: null,
    };
  });

  const suspiciousIp = "198.51.100.23";
  const failures = Array.from({ length: 9 }, (_, index) => ({
    ownerId,
    timestamp: new Date(now - (36 - index * 2) * 60_000),
    eventId: "4625",
    eventType: "Failed Login",
    user: "j.wells",
    sourceIp: suspiciousIp,
    destinationIp: null,
    severity: "Medium",
    status: "Failed",
    description:
      "A Windows Security log records a failed sign-in attempt. This event is simulated.",
    simulated: true,
    anomalyScore: null,
  }));
  const followup = [
    {
      ownerId,
      timestamp: new Date(now - 16 * 60_000),
      eventId: "4624",
      eventType: "Successful Login",
      user: "j.wells",
      sourceIp: suspiciousIp,
      destinationIp: null,
      severity: "High",
      status: "Success",
      description:
        "A successful sign-in followed the simulated failed-login burst from the same address.",
      simulated: true,
      anomalyScore: null,
    },
    {
      ownerId,
      timestamp: new Date(now - 14 * 60_000),
      eventId: "4672",
      eventType: "Privilege Change",
      user: "j.wells",
      sourceIp: suspiciousIp,
      destinationIp: null,
      severity: "High",
      status: "Observed",
      description:
        "A privileged sign-in token was assigned shortly after the simulated authentication sequence.",
      simulated: true,
      anomalyScore: null,
    },
  ];

  return [...normal, ...failures, ...followup].map((event) => ({
    ...event,
    id: randomUUID(),
  }));
}