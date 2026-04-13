package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rohith-97/delta/internal/auth"
	"github.com/rohith-97/delta/internal/tracker"
)

type Server struct {
	auth    *auth.Service
	tracker *tracker.Tracker
}

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Response struct {
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

func main() {
	pgConn := os.Getenv("DATABASE_URL")
	if pgConn == "" {
		pgConn = "postgres://localhost/delta"
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "delta-secret-change-in-production"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "9090"
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := pgxpool.New(ctx, pgConn)
	if err != nil {
		log.Fatalf("failed to connect to postgres: %v", err)
	}

	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("failed to ping postgres: %v", err)
	}

	srv := &Server{
		auth:    auth.NewService(pool, jwtSecret),
		tracker: tracker.NewTracker(pool),
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)

	// public routes
	r.Post("/auth/register", srv.handleRegister)
	r.Post("/auth/login", srv.handleLogin)

	// protected routes
	r.Group(func(r chi.Router) {
		r.Use(srv.authMiddleware)
		r.Get("/me", srv.handleMe)
		r.Get("/activity", srv.handleActivity)
		r.Get("/activity/stats", srv.handleActivityStats)
		r.Get("/suspicious", srv.handleSuspiciousIPs)
	})

	server := &http.Server{
		Addr:    ":" + port,
		Handler: r,
	}

	go func() {
		log.Printf("delta listening on :%s", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("shutting down...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("forced shutdown: %v", err)
	}
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Email == "" || req.Password == "" {
		writeError(w, "username, email and password are required", http.StatusBadRequest)
		return
	}

	user, err := s.auth.Register(r.Context(), req.Username, req.Email, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrUserExists):
			writeError(w, "user already exists", http.StatusConflict)
		case errors.Is(err, auth.ErrWeakPassword):
			writeError(w, err.Error(), http.StatusBadRequest)
		default:
			writeError(w, "registration failed", http.StatusInternalServerError)
		}
		return
	}

	writeJSON(w, map[string]any{
		"id":         user.ID,
		"username":   user.Username,
		"email":      user.Email,
		"created_at": user.CreatedAt,
	}, http.StatusCreated)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ip := r.RemoteAddr
	ua := r.UserAgent()

	token, err := s.auth.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		s.tracker.Log(r.Context(), tracker.Event{
			IP:        ip,
			UserAgent: ua,
			Success:   false,
			Reason:    err.Error(),
		})

		switch {
		case errors.Is(err, auth.ErrAccountLocked):
			writeError(w, err.Error(), http.StatusTooManyRequests)
		case errors.Is(err, auth.ErrInvalidCreds):
			writeError(w, "invalid credentials", http.StatusUnauthorized)
		default:
			writeError(w, "login failed", http.StatusInternalServerError)
		}
		return
	}

	s.tracker.Log(r.Context(), tracker.Event{
		IP:        ip,
		UserAgent: ua,
		Success:   true,
	})

	writeJSON(w, map[string]string{"token": token}, http.StatusOK)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*auth.Claims)
	writeJSON(w, map[string]any{
		"user_id":  claims.UserID,
		"username": claims.Username,
	}, http.StatusOK)
}

func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*auth.Claims)

	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			limit = n
		}
	}

	activities, err := s.tracker.GetActivity(r.Context(), claims.UserID, limit)
	if err != nil {
		writeError(w, "failed to get activity", http.StatusInternalServerError)
		return
	}

	writeJSON(w, activities, http.StatusOK)
}

func (s *Server) handleActivityStats(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*auth.Claims)

	stats, err := s.tracker.Stats(r.Context(), claims.UserID)
	if err != nil {
		writeError(w, "failed to get stats", http.StatusInternalServerError)
		return
	}

	writeJSON(w, stats, http.StatusOK)
}

func (s *Server) handleSuspiciousIPs(w http.ResponseWriter, r *http.Request) {
	threshold := 5
	if t := r.URL.Query().Get("threshold"); t != "" {
		if n, err := strconv.Atoi(t); err == nil {
			threshold = n
		}
	}

	ips, err := s.tracker.GetSuspiciousIPs(r.Context(), threshold)
	if err != nil {
		writeError(w, "failed to get suspicious IPs", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{"suspicious_ips": ips}, http.StatusOK)
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeError(w, "authorization header required", http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			writeError(w, "invalid authorization header", http.StatusUnauthorized)
			return
		}

		claims, err := s.auth.ValidateToken(parts[1])
		if err != nil {
			writeError(w, "invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func writeJSON(w http.ResponseWriter, v any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, msg string, status int) {
	writeJSON(w, Response{Error: msg}, status)
}
