package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"

	"tenant/internal/api"
	"tenant/internal/models"
	"tenant/internal/store"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"golang.org/x/crypto/bcrypt"
)

//go:embed all:dist
var embeddedFiles embed.FS

func main() {
	// Get database config from environment
	// DB_BACKEND: "sqlite" or "turso" (auto-detects if not set)
	// For SQLite: SQLITE_PATH (defaults to "tenant.db")
	// For Turso: TURSO_DATABASE_URL, TURSO_AUTH_TOKEN
	dbConfig := store.ConfigFromEnv()

	// Get port from env or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8069"
	}

	// Check if running in sandbox mode
	sandboxMode := os.Getenv("SANDBOX_MODE") == "true"

	// Initialize store
	s, err := store.New(dbConfig)
	if err != nil {
		log.Fatalf("Failed to initialize store: %v", err)
	}
	defer s.Close()

	// If sandbox mode, ensure sandbox user exists
	if sandboxMode {
		_, err := s.GetUserByUsername("sandbox")
		if err != nil {
			log.Println("Sandbox mode: creating sandbox user")
			passwordHash, _ := bcrypt.GenerateFromPassword([]byte("sandbox"), bcrypt.DefaultCost)
			sandboxUser := &models.User{
				Username:     "sandbox",
				Email:        "sandbox@tenant.social",
				PasswordHash: string(passwordHash),
				DisplayName:  "Sandbox User",
				Bio:          "This is a public sandbox for trying tenant.social. Data may be reset periodically.",
				IsAdmin:      true,
			}
			if err := s.CreateUser(sandboxUser); err != nil {
				log.Fatalf("Failed to create sandbox user: %v", err)
			}
			log.Println("Sandbox user created (username: sandbox, password: sandbox)")
		} else {
			log.Println("Sandbox mode: sandbox user already exists")
		}
	}

	// Auto-create owner from environment variables if set and no users exist
	ownerUsername := os.Getenv("OWNER_USERNAME")
	ownerPassword := os.Getenv("OWNER_PASSWORD")
	if ownerUsername != "" && ownerPassword != "" {
		userCount, err := s.CountUsers()
		if err != nil {
			log.Fatalf("Failed to count users: %v", err)
		}
		if userCount == 0 {
			log.Printf("Creating owner user from environment: %s", ownerUsername)
			passwordHash, _ := bcrypt.GenerateFromPassword([]byte(ownerPassword), bcrypt.DefaultCost)
			ownerUser := &models.User{
				Username:     ownerUsername,
				Email:        ownerUsername + "@tenant.social",
				PasswordHash: string(passwordHash),
				DisplayName:  ownerUsername,
				IsAdmin:      true,
			}
			if err := s.CreateUser(ownerUser); err != nil {
				log.Fatalf("Failed to create owner user: %v", err)
			}
			log.Printf("Owner user created: %s", ownerUsername)
		}
	}

	// Initialize API
	a := api.NewWithSandbox(s, sandboxMode)

	// Setup router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:*", "http://127.0.0.1:*", "https://*.fly.dev"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
	}))

	// API routes
	r.Mount("/api", a.Routes())

	// Serve frontend from embedded files
	distFS, err := fs.Sub(embeddedFiles, "dist")
	if err != nil {
		log.Fatalf("Failed to create sub filesystem: %v", err)
	}
	fileServer := http.FileServer(http.FS(distFS))

	r.Get("/*", func(w http.ResponseWriter, req *http.Request) {
		path := req.URL.Path
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}

		// Check if file exists in embedded FS
		if f, err := distFS.Open(strings.TrimPrefix(path, "/")); err == nil {
			f.Close()
			fileServer.ServeHTTP(w, req)
			return
		}

		// SPA fallback: serve index.html for non-file routes
		req.URL.Path = "/"
		fileServer.ServeHTTP(w, req)
	})

	log.Printf("Tenant starting on http://localhost:%s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
