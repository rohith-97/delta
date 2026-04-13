package auth

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

const (
	bcryptCost    = 12
	tokenExpiry   = 24 * time.Hour
	maxLoginFails = 5
)

var (
	ErrUserExists    = errors.New("user already exists")
	ErrInvalidCreds  = errors.New("invalid credentials")
	ErrAccountLocked = errors.New("account locked due to too many failed attempts")
	ErrWeakPassword  = errors.New("password must be at least 8 characters")
)

type User struct {
	ID        int64
	Username  string
	Email     string
	CreatedAt time.Time
}

type Claims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type Service struct {
	pool      *pgxpool.Pool
	jwtSecret []byte
}

func NewService(pool *pgxpool.Pool, jwtSecret string) *Service {
	return &Service{
		pool:      pool,
		jwtSecret: []byte(jwtSecret),
	}
}

func (s *Service) Register(ctx context.Context, username, email, password string) (*User, error) {
	if len(password) < 8 {
		return nil, ErrWeakPassword
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return nil, err
	}

	var user User
	err = s.pool.QueryRow(ctx,
		`INSERT INTO users (username, email, password)
		 VALUES ($1, $2, $3)
		 RETURNING id, username, email, created_at`,
		username, email, string(hash),
	).Scan(&user.ID, &user.Username, &user.Email, &user.CreatedAt)

	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrUserExists
		}
		return nil, err
	}

	return &user, nil
}

func (s *Service) Login(ctx context.Context, username, password string) (string, error) {
	// get user
	var user User
	var hashedPassword string
	err := s.pool.QueryRow(ctx,
		`SELECT id, username, email, password, created_at
		 FROM users WHERE username = $1`,
		username,
	).Scan(&user.ID, &user.Username, &user.Email, &hashedPassword, &user.CreatedAt)

	if err != nil {
		return "", ErrInvalidCreds
	}

	// check lockout
	locked, err := s.isLocked(ctx, user.ID)
	if err != nil {
		return "", err
	}
	if locked {
		return "", ErrAccountLocked
	}

	// verify password
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		s.logFailedAttempt(ctx, user.ID)
		return "", ErrInvalidCreds
	}

	return s.generateToken(&user)
}

func (s *Service) ValidateToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

func (s *Service) generateToken(user *User) (string, error) {
	claims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

func (s *Service) isLocked(ctx context.Context, userID int64) (bool, error) {
	var count int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM login_activity
		 WHERE user_id = $1
		 AND success = false
		 AND created_at > NOW() - INTERVAL '15 minutes'`,
		userID,
	).Scan(&count)

	if err != nil {
		return false, nil
	}

	return count >= maxLoginFails, nil
}

func (s *Service) logFailedAttempt(ctx context.Context, userID int64) {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO login_activity
			(user_id, ip, user_agent, success, reason, created_at)
		 VALUES ($1, '', '', false, 'invalid password', NOW())`,
		userID,
	)
	if err != nil {
		// non-fatal, just log
		_ = err
	}
}

func isUniqueViolation(err error) bool {
	return err != nil && len(err.Error()) > 0 &&
		contains(err.Error(), "23505")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(s) > 0 && containsRune(s, substr))
}

func containsRune(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
