package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"

	"tenant/internal/api"
	"tenant/internal/store"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

//go:embed all:dist
var embeddedFiles embed.FS

func main() {
	// Get database config from environment
	// DB_BACKEND: "sqlite" or "turso" (auto-detects if not set)
	// For SQLite: SQLITE_PATH (defaults to "eighty.db")
	// For Turso: TURSO_DATABASE_URL, TURSO_AUTH_TOKEN
	dbConfig := store.ConfigFromEnv()

	// Get port from env or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8069"
	}

	// Check if running in production mode
	production := os.Getenv("PRODUCTION") == "true"

	// Initialize store
	s, err := store.New(dbConfig)
	if err != nil {
		log.Fatalf("Failed to initialize store: %v", err)
	}
	defer s.Close()

	// Initialize API
	a := api.New(s)

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

	// Serve frontend
	if production {
		// Production: serve embedded files
		log.Println("Running in production mode with embedded frontend")

		// Get the dist subdirectory from embedded files
		distFS, err := fs.Sub(embeddedFiles, "dist")
		if err != nil {
			log.Fatalf("Failed to get embedded dist: %v", err)
		}

		// Serve static files, fallback to index.html for SPA routing
		fileServer := http.FileServer(http.FS(distFS))
		r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
			// Try to serve the file directly
			path := strings.TrimPrefix(r.URL.Path, "/")
			if path == "" {
				path = "index.html"
			}

			// Check if file exists
			if _, err := fs.Stat(distFS, path); err == nil {
				fileServer.ServeHTTP(w, r)
				return
			}

			// Fallback to index.html for SPA routing
			r.URL.Path = "/"
			fileServer.ServeHTTP(w, r)
		})
	} else {
		// Dev: API only, frontend runs via Vite
		log.Println("Running in dev mode. Frontend: cd web && npm run dev")
	}

	log.Printf("Eighty starting on http://localhost:%s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
