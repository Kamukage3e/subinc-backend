package docmanagement

import (
	"context"
	"errors"
)

func (p *PostgresDocumentStore) Get(ctx context.Context, id string) (*Document, error) {
	// Real prod code: query by id
	row := p.DB.QueryRowContext(ctx, "SELECT id, title, content, owner_id, created_at, updated_at FROM documents WHERE id = $1", id)
	d := &Document{}
	if err := row.Scan(&d.ID, &d.Title, &d.Content, &d.OwnerID, &d.CreatedAt, &d.UpdatedAt); err != nil {
		return nil, err
	}
	return d, nil
}

func (p *PostgresDocumentStore) List(ctx context.Context, filter DocumentFilter) ([]*Document, error) {
	// Real prod code: filter by ownerId and/or title
	q := "SELECT id, title, content, owner_id, created_at, updated_at FROM documents"
	args := []interface{}{}
	where := []string{}
	if filter.OwnerID != nil {
		where = append(where, "owner_id = $1")
		args = append(args, *filter.OwnerID)
	}
	if filter.Title != nil {
		where = append(where, "title ILIKE $2")
		args = append(args, "%"+*filter.Title+"%")
	}
	if len(where) > 0 {
		q += " WHERE " + where[0]
		if len(where) > 1 {
			q += " AND " + where[1]
		}
	}
	rows, err := p.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Document
	for rows.Next() {
		d := &Document{}
		if err := rows.Scan(&d.ID, &d.Title, &d.Content, &d.OwnerID, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

func (p *PostgresDocumentStore) Create(ctx context.Context, input CreateDocumentInput) (*Document, error) {
	row := p.DB.QueryRowContext(ctx, "INSERT INTO documents (title, content, owner_id, created_at, updated_at) VALUES ($1, $2, $3, NOW(), NOW()) RETURNING id, title, content, owner_id, created_at, updated_at", input.Title, input.Content, input.OwnerID)
	d := &Document{}
	if err := row.Scan(&d.ID, &d.Title, &d.Content, &d.OwnerID, &d.CreatedAt, &d.UpdatedAt); err != nil {
		return nil, err
	}
	return d, nil
}

func (p *PostgresDocumentStore) Update(ctx context.Context, id string, input UpdateDocumentInput) (*Document, error) {
	q := "UPDATE documents SET "
	args := []interface{}{}
	set := []string{}
	idx := 1
	if input.Title != nil {
		set = append(set, "title = $"+string(rune(idx)))
		args = append(args, *input.Title)
		idx++
	}
	if input.Content != nil {
		set = append(set, "content = $"+string(rune(idx)))
		args = append(args, *input.Content)
		idx++
	}
	if len(set) == 0 {
		return nil, errors.New("no fields to update")
	}
	q += set[0]
	for i := 1; i < len(set); i++ {
		q += ", " + set[i]
	}
	q += ", updated_at = NOW() WHERE id = $" + string(rune(idx)) + " RETURNING id, title, content, owner_id, created_at, updated_at"
	args = append(args, id)
	row := p.DB.QueryRowContext(ctx, q, args...)
	d := &Document{}
	if err := row.Scan(&d.ID, &d.Title, &d.Content, &d.OwnerID, &d.CreatedAt, &d.UpdatedAt); err != nil {
		return nil, err
	}
	return d, nil
}

func (p *PostgresDocumentStore) Delete(ctx context.Context, id string) error {
	_, err := p.DB.ExecContext(ctx, "DELETE FROM documents WHERE id = $1", id)
	return err
}
