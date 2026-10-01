---
name: Clerk and React patch compatibility
description: Keep React peer-compatibility updates local when a Clerk web artifact needs a newer patch than the shared catalog.
---

When a React web artifact adds Clerk, check the installed Clerk package's React peer range against the workspace catalog. If only that artifact needs a newer React patch, pin React and React DOM in the artifact instead of changing the shared catalog.

**Why:** The workspace React catalog is shared with other apps, including Expo; a workspace-wide patch can affect unrelated compatibility.

**How to apply:** Use a workspace-filtered package update for the affected artifact, keep its exact React and React DOM pins together, and leave the shared catalog unchanged unless all dependent apps have been checked.