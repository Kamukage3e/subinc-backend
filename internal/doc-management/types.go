package docmanagement

import (
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Document struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	OwnerID   string    `json:"ownerId"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type DocumentFilter struct {
	OwnerID *string
	Title   *string
}

type CreateDocumentInput struct {
	Title   string
	Content string
	OwnerID string
}

type UpdateDocumentInput struct {
	Title   *string
	Content *string
}

type Handler struct {
	Store DocumentStore
}

type PostgresDocumentStore struct {
	DB DBTX
}

type Resolver struct {
	Store DocumentStore
}

type PgxPoolDBTX struct {
	Pool *pgxpool.Pool
}

type pgxRowsAdapter struct {
	pgxRows pgx.Rows
}

func (r *pgxRowsAdapter) Next() bool {
	return r.pgxRows.Next()
}

func (r *pgxRowsAdapter) Scan(dest ...interface{}) error {
	return r.pgxRows.Scan(dest...)
}

func (r *pgxRowsAdapter) Close() error {
	r.pgxRows.Close()
	return nil
}

type pgxRowAdapter struct {
	pgxRow pgx.Row
}
