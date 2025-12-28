# Extensibility & Relay Architecture Discussion

*Compiled from discussion on 2025-12-27*

---

## Core Philosophy

**tenant.social** serves three distinct layers:

| Layer | What It Is | Privacy Model | Where Data Lives |
|-------|-----------|---------------|------------------|
| **Personal Data** | Notes, bookmarks, tasks, journals | Private by default. Only you. | Your instance only |
| **Personal Social** | Friends feed, DMs, intimate sharing | Explicit friends only | Your instance + friends' caches |
| **Public/Broad Social** | "Tweets", public posts, discovery | Opt-in broadcast | Your instance + relay(s) |

**Key principle:** These layers are architecturally separate. "Public" on your instance ≠ "broadcast to relay network."

---

## Decisions Made

### 1. Visibility Model: Audiences

Instead of a simple `broadcast` flag, use **audiences** for explicit control:

```rust
Thing {
  visibility: Visibility,      // private | friends | public
  audiences: Vec<Audience>,    // ["relay:main", "relay:indie-hackers"]
}
```

- Empty audiences = not broadcast anywhere (just public on your instance)
- User explicitly opts into specific relays
- UI can make this simple (default to main relay, power users choose)

### 2. Source Attribution: First-Class Fields

For Things imported from external systems:

```rust
Thing {
  // ... existing fields
  source: Option<Source>,
}

Source {
  system: String,           // "pocket", "github", "manual"
  external_id: Option<String>,
  url: Option<String>,
  imported_at: DateTime,
}
```

**Rationale:** Source attribution is fundamental enough to be queryable ("show me all Things from Pocket").

**Open question:** How to prevent staleness when source changes?

### 3. Relay Architecture: Blessed vs Custom

```
┌─────────────────────────────────────────────────────────┐
│                    RELAY NETWORK                         │
├─────────────────────────────────────────────────────────┤
│                                                          │
│   ┌──────────────────┐    ┌──────────────────┐          │
│   │  BLESSED RELAYS  │    │  CUSTOM RELAYS   │          │
│   │  (tenant.social) │    │  (anyone)        │          │
│   │                  │    │                  │          │
│   │  • In default UI │    │  • Add manually  │          │
│   │  • Enforced TOS  │    │  • No guarantees │          │
│   │  • Deletion SLA  │    │  • User's risk   │          │
│   │  • Revshare      │    │  • Open source   │          │
│   │  • Ads possible  │    │  • Warning shown │          │
│   └──────────────────┘    └──────────────────┘          │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

- **Blessed relays:** Run by tenant.social, appear in default UI, enforce privacy/deletion
- **Custom relays:** Anyone can run (open source), users add manually, warnings shown
- Software shows warnings for custom relays: no privacy guarantees

### 4. No Topic-Based Relays

**Rejected:** Topic/category relays like "Rust", "Cooking", etc.

**Instead:** The algorithm IS the relay. Like Twitter's For You feed.

- tenant.social runs "meta-relays" (the main feed)
- Discovery happens via algorithmic relevance, not browsing categories
- Users find people by seeing good posts/replies surface, not by joining communities

**Goal:** Reddit's validation model (upvotes, discussion) + Twitter's relevance model (algorithm, not topics)

### 5. User Actions on Relay

Users can:
- ✅ Read feed
- ✅ React (like, emoji)
- ✅ Reply (threaded, max depth 3)
- ✅ Share/boost to their followers
- ❌ Post directly to relay (posts always originate from your instance)

### 6. Moderation Approach

- **Shadow-ban** illegal (terrorism) and lightly moderate (harassment)
- **Transparency:** Moderation log shows what was demoted (delayed, not real-time)
- **No full censorship:** Content isn't deleted from user's instance, just not amplified
- **Defensible:** "We didn't delete it, we just don't amplify it on our relay"

### 7. Ad/Revenue Model

Acceptable revenue sources for blessed relays:
- ✅ Relay-level sponsors ("This relay brought to you by...")
- ✅ Sponsored posts (clearly labeled)
- ✅ Ads on free tier (premium removes ads)

**Revshare structure (TBD):**
- tenant.social-run relays: Revshare with operators/curators
- tenant.social-hosted but user-run relays: No revshare
- This incentivizes using tenant.social relays → more eyeballs → more revenue

---

## Open Questions

### 1. Paid Accounts / Anti-Spam

**Problem:** Open source means anyone can spin up free instances. How to reduce spam on relays?

**Leading option: Pay-to-broadcast**

| Activity | Cost |
|----------|------|
| Run instance | Free |
| Private data, friends feed | Free |
| API access | Free |
| Read relay | Free |
| React/reply on relay | Free |
| **Post to relay (be discoverable)** | **$3-5 one-time?** |

**Benefits:**
- Open source intact (self-host free)
- Private/friends use free
- Spam dies (cost per account)
- Not a subscription

**Alternatives considered:**
- Free tier + paid verification (doesn't solve spam)
- Invite-only + paid skip (creates cliques)
- Proof of humanity (annoying, gameable)

### 2. Algorithm Signals

What should the relay algorithm weight?

- [ ] Engagement (reactions, shares, replies)
- [ ] Recency
- [ ] Reply quality (good replies boost parent post)
- [ ] Author reputation (past engagement, NOT follower count)
- [ ] Follow graph proximity (who you follow engaged with this)
- [ ] Content signals (length, media, links?)
- [ ] Negative signals (reported, muted by many?)

**Key difference from Twitter:** No follower count worship. A nobody with a great post surfaces. A great reply makes you discoverable.

### 3. Discovery Without Topics

How do users find relays if not topic-based?

- Relay directory (sorted by... popularity? recency?)
- Friend recommendations ("Alice follows these relays")
- Algorithmic suggestions
- Search (for what though?)

**Current thinking:** Most users just use the main tenant.social relay. Power users might discover niche curator-run relays.

### 4. Shadow-Ban Log Timing

When does moderated content appear in the transparency log?

- **Decision:** Delayed (e.g., 7 days)
- **Rationale:** Immediate visibility lets bad actors detect and evade

### 5. Revshare Details (Deferred)

- Who gets revshare? Curator? Operator? Both?
- What percentage split?
- Minimum thresholds?

---

## Technical Implementation Notes

### Push-Based Relay Protocol

Instances push to relay (not relay pulling):

```
Instance                          Relay
   │                                │
   │──POST /relay/ingest ──────────▶│
   │  {                             │
   │    thing_id,                   │
   │    author: "alice@tenant.social",
   │    content,                    │
   │    action: "create"|"update"|"delete"
   │  }                             │
   │                                │
   │◀─── 200 OK ────────────────────│
```

**Why push over pull:**
- Instance controls what relay sees
- Can selectively push
- Better for privacy

### Relay Data Model

```rust
RelayThing {
  id: String,
  source_instance: String,       // "alice.tenant.social"
  source_thing_id: String,       // Original ID on instance
  author_handle: String,         // "alice"
  author_display_name: String,   // Cached
  author_avatar: Option<String>, // Cached (served from instance)
  content: String,
  created_at: DateTime,
  received_at: DateTime,
  deleted: bool,                 // Tombstone for deletions
}
```

### Identity Caching

Relay caches user profile info. Staleness handled by:
1. Instance pushes profile updates to relay
2. Client can fetch fresh profile from instance if needed

### Deletion SLA (Blessed Relays)

```rust
DeletionPolicy {
  soft_delete_within: Duration::hours(1),   // Hide immediately
  hard_delete_within: Duration::hours(24),  // Purge from DB
  propagate_to_caches: true,                // Best effort
  audit_log: true,                          // Track for compliance
}
```

---

## Developer-Facing Extensibility (Priority Order)

### Tier 1: API Foundation
1. **OpenAPI spec** - Auto-generate from Rust types
2. **Webhook subscriptions** - Events → POST to external URLs
3. **Inbound webhooks** - Create Things from external systems

### Tier 2: Developer Tools
1. **TypeScript SDK** - First-class, typed client
2. **Python SDK** - For data/automation crowd
3. **CLI** - Deprioritized for now (SDK + curl covers most cases)

### Tier 3: Integration Patterns
1. **Sync adapters** - Bidirectional sync patterns
2. **Import pipelines** - Twitter archive, Notion export, etc.

---

## Summary of Key Architectural Choices

| Choice | Decision | Rationale |
|--------|----------|-----------|
| Visibility | Audiences (explicit relay opt-in) | User control over broadcast |
| Source attribution | First-class fields | Queryable, consistent |
| Relay trust | Blessed + custom (with warnings) | Balance trust + openness |
| Relay type | Algorithmic, not topic-based | Twitter relevance > Reddit categories |
| User actions on relay | Read/react/share/reply, not post | Posts originate from instance |
| Moderation | Shadow-ban + delayed transparency | Reduce reach, stay defensible |
| Anti-spam | Pay-to-broadcast (TBD) | Friction without breaking open source |
| Push vs pull | Push | Privacy, instance control |

---

## Next Steps

1. Finalize pay-to-broadcast decision
2. Define algorithm signals and weights
3. Design relay API endpoints
4. Implement `audiences` field on Things
5. Implement `source` field on Things
6. Build OpenAPI spec generation
7. Build webhook subscription system
