package docmanagement

import (
	"context"
)

func (r *Resolver) Document(ctx context.Context, id string) (*Document, error) {
	return r.Store.Get(ctx, id)
}

func (r *Resolver) Documents(ctx context.Context, filter *DocumentFilter) ([]*Document, error) {
	if filter == nil {
		return r.Store.List(ctx, DocumentFilter{})
	}
	return r.Store.List(ctx, *filter)
}

func (r *Resolver) CreateDocument(ctx context.Context, input CreateDocumentInput) (*Document, error) {
	return r.Store.Create(ctx, input)
}

func (r *Resolver) UpdateDocument(ctx context.Context, id string, input UpdateDocumentInput) (*Document, error) {
	return r.Store.Update(ctx, id, input)
}

func (r *Resolver) DeleteDocument(ctx context.Context, id string) (bool, error) {
	err := r.Store.Delete(ctx, id)
	if err != nil {
		return false, err
	}
	return true, nil
}


func (r *pgxRowAdapter) Scan(dest ...interface{}) error {
	return r.pgxRow.Scan(dest...)
}

func (p *PgxPoolDBTX) ExecContext(ctx context.Context, query string, args ...interface{}) (Result, error) {
	return p.Pool.Exec(ctx, query, args...)
}

func (p *PgxPoolDBTX) QueryContext(ctx context.Context, query string, args ...interface{}) (Rows, error) {
	r, err := p.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return &pgxRowsAdapter{pgxRows: r}, nil
}

func (p *PgxPoolDBTX) QueryRowContext(ctx context.Context, query string, args ...interface{}) Row {
	return &pgxRowAdapter{pgxRow: p.Pool.QueryRow(ctx, query, args...)}
}
