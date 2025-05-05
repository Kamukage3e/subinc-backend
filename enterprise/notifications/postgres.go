// Package notifications provides a production-grade PostgresNotificationStore for SaaS event delivery.
// All code must be secure, robust, and ready for real-world deployment.
package notifications

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type PostgresNotificationStore struct {
	db     *pgxpool.Pool
	logger *logger.Logger
}

func NewPostgresNotificationStore(db *pgxpool.Pool, log *logger.Logger) *PostgresNotificationStore {
	if log == nil {
		log = logger.NewNoop()
	}
	return &PostgresNotificationStore{db: db, logger: log}
}

func (s *PostgresNotificationStore) Send(ctx context.Context, n *Notification) error {
	if n == nil {
		return ErrInvalidNotification
	}
	_, err := s.db.Exec(ctx, `INSERT INTO notifications (id, type, recipient, subject, body, status, created_at, sent_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		n.ID, n.Type, n.Recipient, n.Subject, n.Body, n.Status, n.CreatedAt, n.SentAt)
	if err != nil {
		s.logger.Error("failed to insert notification", logger.ErrorField(err))
		return err
	}
	return nil
}

func (s *PostgresNotificationStore) GetByID(ctx context.Context, id string) (*Notification, error) {
	row := s.db.QueryRow(ctx, `SELECT id, type, recipient, subject, body, status, created_at, sent_at FROM notifications WHERE id = $1`, id)
	n := &Notification{}
	var sentAt *time.Time
	if err := row.Scan(&n.ID, &n.Type, &n.Recipient, &n.Subject, &n.Body, &n.Status, &n.CreatedAt, &sentAt); err != nil {
		s.logger.Error("failed to get notification by id", logger.ErrorField(err))
		return nil, err
	}
	n.SentAt = sentAt
	return n, nil
}

func (s *PostgresNotificationStore) List(ctx context.Context, recipient, notifType, status string, limit, offset int) ([]*Notification, error) {
	q := `SELECT id, type, recipient, subject, body, status, created_at, sent_at FROM notifications WHERE 1=1`
	args := []interface{}{}
	idx := 1
	if recipient != "" {
		q += ` AND recipient = $` + itoa(idx)
		args = append(args, recipient)
		idx++
	}
	if notifType != "" {
		q += ` AND type = $` + itoa(idx)
		args = append(args, notifType)
		idx++
	}
	if status != "" {
		q += ` AND status = $` + itoa(idx)
		args = append(args, status)
		idx++
	}
	q += ` ORDER BY created_at DESC LIMIT $` + itoa(idx) + ` OFFSET $` + itoa(idx+1)
	args = append(args, limit, offset)
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		s.logger.Error("failed to list notifications", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []*Notification
	for rows.Next() {
		n := &Notification{}
		var sentAt *time.Time
		if err := rows.Scan(&n.ID, &n.Type, &n.Recipient, &n.Subject, &n.Body, &n.Status, &n.CreatedAt, &sentAt); err != nil {
			s.logger.Error("failed to scan notification row", logger.ErrorField(err))
			return nil, err
		}
		n.SentAt = sentAt
		out = append(out, n)
	}
	return out, nil
}

func (s *PostgresNotificationStore) MarkSent(ctx context.Context, id string, sentAt time.Time) error {
	_, err := s.db.Exec(ctx, `UPDATE notifications SET status = 'sent', sent_at = $1 WHERE id = $2`, sentAt, id)
	if err != nil {
		s.logger.Error("failed to mark notification sent", logger.ErrorField(err))
		return err
	}
	return nil
}

var ErrInvalidNotification = &NotificationError{"invalid notification"}

type NotificationError struct{ msg string }

func (e *NotificationError) Error() string { return e.msg }

func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}
