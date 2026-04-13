package tracker

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Event struct {
	UserID    int64
	IP        string
	UserAgent string
	Success   bool
	Reason    string
}

type LoginActivity struct {
	ID        int64
	UserID    int64
	IP        string
	UserAgent string
	Success   bool
	Reason    string
	CreatedAt time.Time
}

type Tracker struct {
	pool *pgxpool.Pool
}

func NewTracker(pool *pgxpool.Pool) *Tracker {
	return &Tracker{pool: pool}
}

func (t *Tracker) Log(ctx context.Context, event Event) {
	_, err := t.pool.Exec(ctx,
		`INSERT INTO login_activity
			(user_id, ip, user_agent, success, reason, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		nullableInt64(event.UserID),
		event.IP,
		event.UserAgent,
		event.Success,
		nullableString(event.Reason),
		time.Now(),
	)
	if err != nil {
		log.Printf("tracker log error: %v", err)
	}
}

func (t *Tracker) GetActivity(ctx context.Context, userID int64, limit int) ([]LoginActivity, error) {
	rows, err := t.pool.Query(ctx,
		`SELECT id, user_id, ip, user_agent, success, reason, created_at
		 FROM login_activity
		 WHERE user_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2`,
		userID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var activities []LoginActivity
	for rows.Next() {
		var a LoginActivity
		var reason *string
		if err := rows.Scan(
			&a.ID,
			&a.UserID,
			&a.IP,
			&a.UserAgent,
			&a.Success,
			&reason,
			&a.CreatedAt,
		); err != nil {
			return nil, err
		}
		if reason != nil {
			a.Reason = *reason
		}
		activities = append(activities, a)
	}

	return activities, nil
}

func (t *Tracker) GetSuspiciousIPs(ctx context.Context, threshold int) ([]string, error) {
	rows, err := t.pool.Query(ctx,
		`SELECT ip FROM login_activity
		 WHERE success = false
		 AND created_at > NOW() - INTERVAL '1 hour'
		 GROUP BY ip
		 HAVING COUNT(*) >= $1
		 ORDER BY COUNT(*) DESC`,
		threshold,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

func (t *Tracker) Stats(ctx context.Context, userID int64) (map[string]any, error) {
	row := t.pool.QueryRow(ctx,
		`SELECT
			COUNT(*) as total,
			COUNT(CASE WHEN success = true THEN 1 END) as successful,
			COUNT(CASE WHEN success = false THEN 1 END) as failed,
			COUNT(DISTINCT ip) as unique_ips
		 FROM login_activity
		 WHERE user_id = $1`,
		userID,
	)

	var total, successful, failed, uniqueIPs int
	if err := row.Scan(&total, &successful, &failed, &uniqueIPs); err != nil {
		return nil, err
	}

	return map[string]any{
		"total":      total,
		"successful": successful,
		"failed":     failed,
		"unique_ips": uniqueIPs,
	}, nil
}

func nullableInt64(i int64) *int64 {
	if i == 0 {
		return nil
	}
	return &i
}

func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
