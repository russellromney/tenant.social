# Tenant.social Memory Optimization Plan

## Goal
Reduce per-VM memory footprint from **100MB → 15-20MB** to enable high-density multi-tenancy (1000+ VMs per 16GB host).

## Current State (Go)

```
Memory breakdown (~100MB per instance):
├─ Go binary with embedded assets: 20MB
├─ Go runtime + GC: 10-15MB
├─ HTTP server (net/http): 5MB
├─ SQLite in-memory cache: 10-20MB
├─ Active connections/buffers: 10MB
├─ Preact bundle (embedded): 5MB
└─ Misc overhead: 30-40MB
```

**Density:** 16GB host = ~150 VMs

---

## Phase 1: Quick Wins (Go Optimizations)

**Target:** 100MB → 40-50MB
**Effort:** 1-2 days
**ROI:** 2-3x density improvement

### 1.1 Move Frontend to Tigris CDN
```go
// Remove embed.FS
// Serve static files from Tigris instead

// Before:
//go:embed web/dist/*
var assets embed.FS

// After:
func handleFrontend(w http.ResponseWriter, r *http.Request) {
    cdnURL := os.Getenv("TIGRIS_STATIC_URL")
    http.Redirect(w, r, cdnURL+r.URL.Path, http.StatusMovedPermanently)
}
```

**Savings:** ~40-50MB per VM (no embedded assets)

### 1.2 SQLite Optimization
```go
db.Exec("PRAGMA cache_size = 100")        // Default: 2000 pages
db.Exec("PRAGMA page_size = 1024")        // Smaller pages
db.Exec("PRAGMA journal_mode = WAL")      // More efficient
db.Exec("PRAGMA synchronous = NORMAL")    // Less fsync
db.Exec("PRAGMA temp_store = MEMORY")     // Temp tables in RAM
db.Exec("PRAGMA mmap_size = 0")           // Disable mmap
```

**Savings:** ~10-15MB per VM

### 1.3 Build Flags
```bash
CGO_ENABLED=0 go build \
  -ldflags="-s -w" \        # Strip symbols
  -trimpath \               # Remove build paths
  -o tenant ./cmd/tenant
```

**Savings:** ~5-10MB binary size

### 1.4 Aggressive GOMEMLIMIT
```bash
GOMEMLIMIT=40MiB ./tenant
```

Forces Go GC to stay under 40MB

**Savings:** ~10-20MB per VM

**Phase 1 Result:** ~40-50MB per VM = 300-400 VMs per 16GB host

---

## Phase 2: Rust Rewrite (Target)

**Target:** 40-50MB → 15-20MB
**Effort:** 1 week
**ROI:** 6-10x density vs current

### 2.1 Architecture

```
Rust Tenant VM:
├─ Actix-web HTTP server
├─ Rusqlite for SQLite
├─ Minimal dependencies
└─ No GC, no runtime overhead
```

### 2.2 Memory Breakdown (Rust)

```
Expected memory (~15-20MB per VM):
├─ Binary: 3MB (stripped)
├─ Runtime: 2MB (no GC!)
├─ SQLite: 3-5MB (optimized)
├─ HTTP server: 2-3MB
├─ WebSocket/channels: 2MB
├─ Buffers/connections: 2-3MB
└─ Total: ~15-20MB
```

**Density:** 16GB host = ~800-1000 VMs

### 2.3 Dependencies

```toml
[dependencies]
actix-web = "4.4"           # HTTP + WebSocket (fast, battle-tested)
actix-ws = "0.3"            # WebSocket support
rusqlite = "0.30"           # SQLite (zero-copy, minimal)
tokio = "1.0"               # Async runtime (efficient)
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
chrono = "0.4"              # DateTime handling
uuid = { version = "1.0", features = ["v4"] }
bcrypt = "0.15"             # Password hashing
jsonwebtoken = "9.0"        # JWT auth
```

### 2.4 Build Configuration

```toml
[profile.release]
opt-level = "z"             # Optimize for size
lto = true                  # Link-time optimization
codegen-units = 1           # Single codegen unit
strip = true                # Strip symbols
panic = "abort"             # Smaller panic handler
```

```bash
# Build command
cargo build --release --target x86_64-unknown-linux-musl
```

**Result:** ~3MB static binary

### 2.5 SQLite Optimizations (Rust)

```rust
let conn = Connection::open("tenant.db")?;
conn.execute_batch(r#"
    PRAGMA cache_size = 100;
    PRAGMA page_size = 1024;
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA temp_store = MEMORY;
    PRAGMA mmap_size = 0;
    PRAGMA locking_mode = EXCLUSIVE;
"#)?;
```

### 2.6 Feature Parity Checklist

- [x] SQLite CRUD operations
- [x] User authentication (bcrypt)
- [x] Session management (JWT)
- [x] Things API (create/read/update/delete)
- [x] Photo uploads (multipart)
- [x] Friendships (graph queries)
- [x] Channels/messaging (WebSocket)
- [x] Real-time notifications (SSE/WebSocket)
- [x] API key authentication
- [x] Scoped permissions

**Implementation Time:** ~5-7 days

---

## Phase 3: Advanced Optimizations

**Target:** 15-20MB → 10-15MB
**Effort:** 1-2 weeks (if needed)
**ROI:** Marginal, only if hitting limits

### 3.1 Custom Allocator

```toml
[dependencies]
mimalloc = "0.1"  # Microsoft's malloc (more efficient)
```

```rust
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
```

**Savings:** ~2-3MB per VM

### 3.2 Jemalloc Profiling

```bash
# Profile memory usage
MALLOC_CONF=prof:true ./tenant
jeprof --pdf ./tenant jeprof.*.heap > profile.pdf
```

Identify memory hotspots and optimize

### 3.3 Remove Unused Features

```toml
# Disable unused tokio features
tokio = { version = "1.0", default-features = false, features = ["rt-multi-thread", "macros", "net"] }

# Minimal TLS (if not using HTTPS in VM)
actix-web = { version = "4.4", default-features = false, features = ["macros"] }
```

**Savings:** ~1-2MB per VM

### 3.4 Consider Zig/C (if extreme optimization needed)

Only if Rust doesn't hit targets (unlikely)

```
C/Zig VM:
├─ Binary: 1-2MB
├─ Runtime: 2-3MB
├─ SQLite: 3-5MB
└─ Total: ~7-10MB
```

**Not recommended:** Maintenance burden too high

---

## Deployment Architecture

### Production Deployment (Nomad Orchestration)

Instead of building a custom Firecracker supervisor, use **Nomad** for orchestration (battle-tested, used by HashiCorp/industry):

```
┌──────────────────────────────────────────┐
│  Load Balancer / Reverse Proxy           │
│  Routes user123.tenant.social → VM       │
│  Consul DNS for service discovery        │
└──────────────┬───────────────────────────┘
               │
    ┌──────────┼──────────┬──────────┐
    │          │          │          │
    ▼          ▼          ▼          ▼
┌─────────┐ ┌──────┐ ┌──────┐ ┌──────────┐
│ Nomad   │ │Host1 │ │Host2 │ │Host N    │
│ Server  │ │(16GB)│ │(16GB)│ │(16GB)    │
│ (UI)    │ └──────┘ └──────┘ └──────────┘
└─────────┘
   │
   │ Orchestrates across all hosts
   │
   ├─ tenant-vm #1-400 (Host1)
   ├─ tenant-vm #401-800 (Host2)
   ├─ tenant-vm #801+ (Host N)
   │
   └─ Health checks, auto-restart, scaling
```

### Single Host Deployment (MVP)

```
┌─────────────────────────────────┐
│  Single 16GB Server             │
├─────────────────────────────────┤
│  Nomad Server (control plane)   │
│  Nomad Client (runs jobs)       │
│                                 │
│  ├─ tenant-vm #1 (15MB)         │
│  ├─ tenant-vm #2 (15MB)         │
│  ├─ tenant-vm #3 (15MB)         │
│  └─ ... up to 800+ instances    │
│                                 │
│  UI: http://server:4646         │
└─────────────────────────────────┘

Capacity: ~800 users per box
Cost: ~€50/month
```

### Nomad Job Specification

**tenant-vm.nomad:**
```hcl
job "tenant-vm" {
  region      = "us-east"
  datacenters = ["dc1"]
  type        = "service"

  group "tenant-vms" {
    count = 10  # Scale: nomad job scale tenant-vm 100

    task "tenant-vm" {
      driver = "docker"

      config {
        image = "your-registry/tenant-vm:latest"
        ports = ["http"]
        volumes = [
          "/data/tenant-${NOMAD_ALLOC_ID}/tenant.db:/app/tenant.db"
        ]
      }

      resources {
        cpu    = 100   # 100 MHz per instance
        memory = 64    # 64 MB per instance (lean!)
      }

      network {
        mode = "bridge"
        port "http" {
          to = 8069
        }
      }

      env {
        PORT = "8069"
        OWNER_USERNAME = "user-${NOMAD_TASK_NAME}"
        DATABASE_PATH = "/app/tenant.db"
      }

      service {
        name = "tenant-vm"
        port = "http"

        check {
          type     = "http"
          port     = "http"
          path     = "/api/health"
          interval = "10s"
          timeout  = "5s"
        }

        tags = ["user-id-${NOMAD_ALLOC_ID}"]
      }
    }
  }

  update {
    max_parallel      = 2
    health_check      = "checks"
    min_healthy_time  = "10s"
    auto_revert       = true
  }
}
```

### Reverse Proxy (Routing)

Simple reverse proxy to route requests to tenant VMs based on subdomain/path:

```rust
// Queries Consul service discovery for tenant VM
// Routes user123.tenant.social → tenant-vm service with tag "user-id-{user123}"
// Starts VM on-demand if not running
pub async fn reverse_proxy(req: Request<Body>) -> Response<Body> {
    let user_id = extract_user(&req);

    // Query Consul for this user's tenant-vm
    let services = consul.get_service("tenant-vm")
        .filter(|s| s.tags.contains(&format!("user-id-{}", user_id)))
        .await?;

    if services.is_empty() {
        // Start VM via Nomad if not running
        nomad.dispatch_job("tenant-vm", &user_id).await?;
        return retry_with_backoff(5).await;
    }

    // Proxy to the tenant VM
    proxy_request_to(services[0].address, req).await
}
```

### Scaling (Simple)

```bash
# Scale to 100 instances across all hosts
nomad job scale tenant-vm 100

# Scale to 500
nomad job scale tenant-vm 500

# Nomad automatically distributes across available hosts
# No code changes, no infrastructure redesign
```

### Deployment Flow

```bash
# 1. Build Docker image
docker build -t your-registry/tenant-vm:latest .
docker push your-registry/tenant-vm:latest

# 2. Deploy to Nomad
nomad job run tenant-vm.nomad

# 3. Monitor
nomad status tenant-vm
nomad ui  # Web dashboard at :4646

# 4. Update (rolling deployment)
# - Push new image
nomad job run tenant-vm.nomad  # Deploys 2 at a time, health checks
```

### Advantages vs Custom Supervisor

| Feature | Nomad | Custom Supervisor |
|---------|-------|-------------------|
| **Complexity** | Simple HCL config | 1000+ lines of Rust code |
| **Maintenance** | Proven, industry standard | Custom ops burden |
| **Scaling** | `nomad job scale X` | Custom implementation |
| **Monitoring** | Built-in UI + API | Must build dashboard |
| **Health checks** | Built-in | Must implement |
| **Multi-host** | Native support | Complex coordination |
| **Community** | Large, active | None |
| **Time to deploy** | 1 day | 2-3 weeks |

---

## Why Nomad Over Custom Firecracker Supervisor?

**The Plan initially proposed a custom Rust supervisor with Firecracker**, similar to Fly.io's architecture. However:

1. **Fly.io built `flyd` because:**
   - They're funded with an infra team
   - Custom optimizations were worth the cost at scale
   - They needed extreme customization

2. **For tenant.social:**
   - Nomad gives you 90% of the benefits with 1% of the complexity
   - Scale later if needed (Nomad → Firecracker is an upgrade path)
   - Deploy faster, focus on product

3. **The math:**
   - Rust tenant-vm: 15-20MB per instance
   - Nomad orchestration: off-the-shelf
   - 800 users/host: achieved with simple tooling
   - ROI on custom supervisor only at 10,000+ users

---

## Economics

### Current (Go - 100MB)
```
Hetzner AX41: €41/month
├─ 64GB RAM
├─ Capacity: ~600 stopped VMs, ~60 running
├─ Revenue at $1/VM: $600/month
└─ Profit: $559/month (~13.6x)
```

### Phase 1 (Go - 40MB)
```
Hetzner AX41: €41/month
├─ 64GB RAM
├─ Capacity: ~1,500 stopped VMs, ~150 running
├─ Revenue at $1/VM: $1,500/month
└─ Profit: $1,459/month (~35.6x)
```

### Phase 2 (Rust - 15-20MB)
```
Hetzner AX41: €41/month
├─ 64GB RAM
├─ Capacity: ~3,000 stopped VMs, ~800 running
├─ Revenue at $1/VM: $3,000/month
└─ Profit: $2,959/month (~72x)
```

---

## Implementation Timeline

### Week 1: Quick Wins (Go)
- Day 1-2: Move frontend to Tigris, SQLite optimization
- Day 3-4: Build flags, GOMEMLIMIT testing
- Day 5: Measure & verify 40-50MB target

**Milestone:** 2-3x density improvement, production ready

### Week 2-3: Rust Rewrite
- Day 1-2: Models & SQLite layer
- Day 3-4: HTTP API endpoints (CRUD)
- Day 5-6: Auth (sessions, JWT, API keys)
- Day 7-8: Photos, friendships, channels
- Day 9-10: WebSocket, real-time features
- Day 11-12: Testing, benchmarks
- Day 13-14: Deploy, measure, iterate

**Milestone:** 6-10x density improvement

### Week 4: Production Rollout
- Parallel deployment (Go + Rust VMs)
- Gradual migration
- Monitoring & optimization

---

## Success Metrics

| Phase | Memory/VM | VMs/16GB | Binary Size | Cold Start |
|-------|-----------|----------|-------------|------------|
| Current | 100MB | 150 | 20MB | ~500ms |
| Phase 1 | 40-50MB | 300-400 | 5MB | ~300ms |
| Phase 2 | 15-20MB | 800-1000 | 3MB | ~100ms |

---

## Risk Mitigation

### Rust Learning Curve
- **Mitigation:** Start with Phase 1 (Go), gives time to learn Rust
- **Resources:** Rust Book, actix-web examples, existing Go code as reference

### Feature Parity
- **Mitigation:** Comprehensive test suite, gradual migration
- **Validation:** Run both Go and Rust side-by-side initially

### Production Issues
- **Mitigation:** Rust's safety guarantees prevent memory bugs
- **Fallback:** Keep Go version running, can rollback

---

## Next Steps

1. ✅ Create this optimization plan
2. ✅ Build Rust tenant-vm backend (Phase 2)
3. ✅ Implement core APIs (Things, Auth, Photos, Backlinks)
4. ⬜ Build Docker image for tenant-vm
5. ⬜ Set up Nomad cluster (single host initially)
6. ⬜ Deploy tenant-vm via Nomad
7. ⬜ Implement reverse proxy/routing (Consul integration)
8. ⬜ Test scaling to 100+ instances
9. ⬜ Load test and optimize
10. ⬜ Multi-host Nomad deployment
11. ⬜ Production rollout

---

## Future: Custom Supervisor (If Needed)

If you ever need extreme optimization beyond Nomad (at 10,000+ users):
- The architecture supports migration to Firecracker + custom supervisor
- Nomad skills transfer to orchestrating Firecracker VMs
- Start simple, scale with proven tools first

---

## References

- [Nomad Documentation](https://www.nomadproject.io/docs)
- [Consul Service Discovery](https://www.consul.io/docs)
- [Actix-web Documentation](https://actix.rs/)
- [Rusqlite Documentation](https://docs.rs/rusqlite/)
- [The Rust Book](https://doc.rust-lang.org/book/)
- [Tokio Async Runtime](https://tokio.rs/)
- [Fly.io Stack](https://fly.io/docs/hiring/stack/) - Architecture reference
- [Docker Documentation](https://docs.docker.com/)
