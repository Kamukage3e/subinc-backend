package organization_management

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	security_management "github.com/subinc/subinc-backend/internal/admin/security-management"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

type PostgresStore struct {
	db          *sql.DB
	logger      *logger.Logger
	AuditLogger security_management.AuditLogger
}

func NewPostgresStore(db *sql.DB, log *logger.Logger) *PostgresStore {
	if log == nil {
		log = logger.NewNoop()
	}
	return &PostgresStore{db: db, logger: log}
}

// OrganizationService
func (s *PostgresStore) CreateOrganization(ctx context.Context, org Organization) (Organization, error) {
	const q = `INSERT INTO organizations (id, name, slug, owner_id, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name, slug, owner_id, status, created_at, updated_at`
	id := uuid.NewString()
	now := time.Now().UTC()
	row := s.db.QueryRowContext(ctx, q, id, org.Name, org.Slug, org.OwnerID, org.Status, now, now)
	var out Organization
	if err := row.Scan(&out.ID, &out.Name, &out.Slug, &out.OwnerID, &out.Status, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("CreateOrganization failed", logger.ErrorField(err), logger.Any("org", org))
		return Organization{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdateOrganization(ctx context.Context, org Organization) (Organization, error) {
	const q = `UPDATE organizations SET name = $2, slug = $3, owner_id = $4, status = $5, updated_at = $6 WHERE id = $1 RETURNING id, name, slug, owner_id, status, created_at, updated_at`
	row := s.db.QueryRowContext(ctx, q, org.ID, org.Name, org.Slug, org.OwnerID, org.Status, time.Now().UTC())
	var out Organization
	if err := row.Scan(&out.ID, &out.Name, &out.Slug, &out.OwnerID, &out.Status, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("UpdateOrganization failed", logger.ErrorField(err), logger.Any("org", org))
		return Organization{}, err
	}
	return out, nil
}

func (s *PostgresStore) DeleteOrganization(ctx context.Context, id string) error {
	const q = `DELETE FROM organizations WHERE id = $1`
	_, err := s.db.ExecContext(ctx, q, id)
	if err != nil {
		s.logger.Error("DeleteOrganization failed", logger.ErrorField(err), logger.String("id", id))
	}
	return err
}

func (s *PostgresStore) GetOrganization(ctx context.Context, id string) (Organization, error) {
	const q = `SELECT id, name, slug, owner_id, status, created_at, updated_at FROM organizations WHERE id = $1`
	row := s.db.QueryRowContext(ctx, q, id)
	var out Organization
	if err := row.Scan(&out.ID, &out.Name, &out.Slug, &out.OwnerID, &out.Status, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("GetOrganization failed", logger.ErrorField(err), logger.String("id", id))
		return Organization{}, err
	}
	return out, nil
}

func (s *PostgresStore) ListOrganizations(ctx context.Context, ownerID string, page, pageSize int) ([]Organization, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	const q = `SELECT id, name, slug, owner_id, status, created_at, updated_at FROM organizations WHERE owner_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	offset := (page - 1) * pageSize
	rows, err := s.db.QueryContext(ctx, q, ownerID, pageSize, offset)
	if err != nil {
		s.logger.Error("ListOrganizations query failed", logger.ErrorField(err), logger.String("owner_id", ownerID))
		return nil, err
	}
	defer rows.Close()
	var out []Organization
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.OwnerID, &o.Status, &o.CreatedAt, &o.UpdatedAt); err != nil {
			s.logger.Error("ListOrganizations scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, o)
	}
	return out, nil
}

// OrgMemberService
func (s *PostgresStore) AddMember(ctx context.Context, member OrgMember) (OrgMember, error) {
	const q = `INSERT INTO org_members (id, org_id, user_id, role, status, invited_by, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, org_id, user_id, role, status, invited_by, created_at, updated_at`
	id := uuid.NewString()
	now := time.Now().UTC()
	row := s.db.QueryRowContext(ctx, q, id, member.OrgID, member.UserID, member.Role, member.Status, member.InvitedBy, now, now)
	var out OrgMember
	if err := row.Scan(&out.ID, &out.OrgID, &out.UserID, &out.Role, &out.Status, &out.InvitedBy, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("AddMember failed", logger.ErrorField(err), logger.Any("member", member))
		return OrgMember{}, err
	}
	return out, nil
}

func (s *PostgresStore) RemoveMember(ctx context.Context, id string) error {
	const q = `DELETE FROM org_members WHERE id = $1`
	_, err := s.db.ExecContext(ctx, q, id)
	if err != nil {
		s.logger.Error("RemoveMember failed", logger.ErrorField(err), logger.String("id", id))
	}
	return err
}

func (s *PostgresStore) UpdateMemberRole(ctx context.Context, id, role string) error {
	const q = `UPDATE org_members SET role = $2, updated_at = $3 WHERE id = $1`
	_, err := s.db.ExecContext(ctx, q, id, role, time.Now().UTC())
	if err != nil {
		s.logger.Error("UpdateMemberRole failed", logger.ErrorField(err), logger.String("id", id))
	}
	return err
}

func (s *PostgresStore) ListMembers(ctx context.Context, orgID string, page, pageSize int) ([]OrgMember, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	const q = `SELECT id, org_id, user_id, role, status, invited_by, created_at, updated_at FROM org_members WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	offset := (page - 1) * pageSize
	rows, err := s.db.QueryContext(ctx, q, orgID, pageSize, offset)
	if err != nil {
		s.logger.Error("ListMembers query failed", logger.ErrorField(err), logger.String("org_id", orgID))
		return nil, err
	}
	defer rows.Close()
	var out []OrgMember
	for rows.Next() {
		var m OrgMember
		if err := rows.Scan(&m.ID, &m.OrgID, &m.UserID, &m.Role, &m.Status, &m.InvitedBy, &m.CreatedAt, &m.UpdatedAt); err != nil {
			s.logger.Error("ListMembers scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func (s *PostgresStore) UpdateMember(ctx context.Context, member OrgMember) (OrgMember, error) {
	const q = `UPDATE org_members SET org_id = $2, user_id = $3, role = $4, status = $5, invited_by = $6, updated_at = $7 WHERE id = $1 RETURNING id, org_id, user_id, role, status, invited_by, created_at, updated_at`
	row := s.db.QueryRowContext(ctx, q, member.ID, member.OrgID, member.UserID, member.Role, member.Status, member.InvitedBy, time.Now().UTC())
	var out OrgMember
	if err := row.Scan(&out.ID, &out.OrgID, &out.UserID, &out.Role, &out.Status, &out.InvitedBy, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("UpdateMember failed", logger.ErrorField(err), logger.Any("member", member))
		return OrgMember{}, err
	}
	return out, nil
}

func (s *PostgresStore) GetMember(ctx context.Context, id string) (OrgMember, error) {
	const q = `SELECT id, org_id, user_id, role, status, invited_by, created_at, updated_at FROM org_members WHERE id = $1`
	row := s.db.QueryRowContext(ctx, q, id)
	var out OrgMember
	if err := row.Scan(&out.ID, &out.OrgID, &out.UserID, &out.Role, &out.Status, &out.InvitedBy, &out.CreatedAt, &out.UpdatedAt); err != nil {
		s.logger.Error("GetMember failed", logger.ErrorField(err), logger.String("id", id))
		return OrgMember{}, err
	}
	return out, nil
}

// OrgInviteService
func (s *PostgresStore) CreateInvite(ctx context.Context, invite OrgInvite) (OrgInvite, error) {
	const q = `INSERT INTO org_invites (id, org_id, email, role, status, token, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, org_id, email, role, status, token, expires_at, created_at`
	id := uuid.NewString()
	now := time.Now().UTC()
	row := s.db.QueryRowContext(ctx, q, id, invite.OrgID, invite.Email, invite.Role, invite.Status, invite.Token, invite.ExpiresAt, now)
	var out OrgInvite
	if err := row.Scan(&out.ID, &out.OrgID, &out.Email, &out.Role, &out.Status, &out.Token, &out.ExpiresAt, &out.CreatedAt); err != nil {
		s.logger.Error("CreateInvite failed", logger.ErrorField(err), logger.Any("invite", invite))
		return OrgInvite{}, err
	}
	return out, nil
}

func (s *PostgresStore) AcceptInvite(ctx context.Context, token string) error {
	const q = `UPDATE org_invites SET status = 'accepted' WHERE token = $1 AND status = 'pending'`
	_, err := s.db.ExecContext(ctx, q, token)
	if err != nil {
		s.logger.Error("AcceptInvite failed", logger.ErrorField(err), logger.String("token", token))
	}
	return err
}

func (s *PostgresStore) RevokeInvite(ctx context.Context, id string) error {
	const q = `UPDATE org_invites SET status = 'revoked' WHERE id = $1`
	_, err := s.db.ExecContext(ctx, q, id)
	if err != nil {
		s.logger.Error("RevokeInvite failed", logger.ErrorField(err), logger.String("id", id))
	}
	return err
}

func (s *PostgresStore) ListInvites(ctx context.Context, orgID string, page, pageSize int) ([]OrgInvite, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	const q = `SELECT id, org_id, email, role, status, token, expires_at, created_at FROM org_invites WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	offset := (page - 1) * pageSize
	rows, err := s.db.QueryContext(ctx, q, orgID, pageSize, offset)
	if err != nil {
		s.logger.Error("ListInvites query failed", logger.ErrorField(err), logger.String("org_id", orgID))
		return nil, err
	}
	defer rows.Close()
	var out []OrgInvite
	for rows.Next() {
		var i OrgInvite
		if err := rows.Scan(&i.ID, &i.OrgID, &i.Email, &i.Role, &i.Status, &i.Token, &i.ExpiresAt, &i.CreatedAt); err != nil {
			s.logger.Error("ListInvites scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, i)
	}
	return out, nil
}

// OrgDomainService
func (s *PostgresStore) AddDomain(ctx context.Context, domain OrgDomain) (OrgDomain, error) {
	const q = `INSERT INTO org_domains (id, org_id, domain, verified, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING id, org_id, domain, verified, created_at`
	id := uuid.NewString()
	now := time.Now().UTC()
	row := s.db.QueryRowContext(ctx, q, id, domain.OrgID, domain.Domain, domain.Verified, now)
	var out OrgDomain
	if err := row.Scan(&out.ID, &out.OrgID, &out.Domain, &out.Verified, &out.CreatedAt); err != nil {
		s.logger.Error("AddDomain failed", logger.ErrorField(err), logger.Any("domain", domain))
		return OrgDomain{}, err
	}
	return out, nil
}

func (s *PostgresStore) VerifyDomain(ctx context.Context, id string) error {
	const q = `UPDATE org_domains SET verified = true WHERE id = $1`
	_, err := s.db.ExecContext(ctx, q, id)
	if err != nil {
		s.logger.Error("VerifyDomain failed", logger.ErrorField(err), logger.String("id", id))
	}
	return err
}

func (s *PostgresStore) RemoveDomain(ctx context.Context, id string) error {
	const q = `DELETE FROM org_domains WHERE id = $1`
	_, err := s.db.ExecContext(ctx, q, id)
	if err != nil {
		s.logger.Error("RemoveDomain failed", logger.ErrorField(err), logger.String("id", id))
	}
	return err
}

func (s *PostgresStore) ListDomains(ctx context.Context, orgID string) ([]OrgDomain, error) {
	const q = `SELECT id, org_id, domain, verified, created_at FROM org_domains WHERE org_id = $1 ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, q, orgID)
	if err != nil {
		s.logger.Error("ListDomains query failed", logger.ErrorField(err), logger.String("org_id", orgID))
		return nil, err
	}
	defer rows.Close()
	var out []OrgDomain
	for rows.Next() {
		var d OrgDomain
		if err := rows.Scan(&d.ID, &d.OrgID, &d.Domain, &d.Verified, &d.CreatedAt); err != nil {
			s.logger.Error("ListDomains scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// OrgSettingsService
func (s *PostgresStore) GetSettings(ctx context.Context, orgID string) (OrgSettings, error) {
	const q = `SELECT org_id, settings, updated_at FROM org_settings WHERE org_id = $1`
	row := s.db.QueryRowContext(ctx, q, orgID)
	var out OrgSettings
	if err := row.Scan(&out.OrgID, &out.Settings, &out.UpdatedAt); err != nil {
		s.logger.Error("GetSettings failed", logger.ErrorField(err), logger.String("org_id", orgID))
		return OrgSettings{}, err
	}
	return out, nil
}

func (s *PostgresStore) UpdateSettings(ctx context.Context, orgID, settings string) error {
	const q = `UPDATE org_settings SET settings = $2, updated_at = $3 WHERE org_id = $1`
	_, err := s.db.ExecContext(ctx, q, orgID, settings, time.Now().UTC())
	if err != nil {
		s.logger.Error("UpdateSettings failed", logger.ErrorField(err), logger.String("org_id", orgID))
	}
	return err
}

// OrgAuditLogService
func (s *PostgresStore) logAudit(ctx context.Context, log OrgAuditLog) {
	if s.AuditLogger == nil {
		s.AuditLogger = security_management.NoopAuditLogger{}
	}
	_, _ = s.AuditLogger.CreateSecurityAuditLog(ctx, security_management.SecurityAuditLog{
		ID:        log.ID,
		ActorID:   log.ActorID,
		Action:    log.Action,
		TargetID:  log.TargetID,
		Details:   log.Details,
		CreatedAt: log.CreatedAt,
	})
}

func (s *PostgresStore) CreateAuditLog(ctx context.Context, log OrgAuditLog) (OrgAuditLog, error) {
	const q = `INSERT INTO org_audit_logs (id, org_id, actor_id, action, target_id, details, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, org_id, actor_id, action, target_id, details, created_at`
	id := uuid.NewString()
	now := time.Now().UTC()
	row := s.db.QueryRowContext(ctx, q, id, log.OrgID, log.ActorID, log.Action, log.TargetID, log.Details, now)
	var out OrgAuditLog
	if err := row.Scan(&out.ID, &out.OrgID, &out.ActorID, &out.Action, &out.TargetID, &out.Details, &out.CreatedAt); err != nil {
		s.logger.Error("CreateAuditLog failed", logger.ErrorField(err), logger.Any("log", log))
		return OrgAuditLog{}, err
	}
	s.logAudit(ctx, out)
	return out, nil
}

func (s *PostgresStore) ListAuditLogs(ctx context.Context, orgID, actorID, action string, page, pageSize int) ([]OrgAuditLog, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}
	q := `SELECT id, org_id, actor_id, action, target_id, details, created_at FROM org_audit_logs WHERE org_id = $1`
	args := []interface{}{orgID}
	if actorID != "" {
		q += " AND actor_id = $2"
		args = append(args, actorID)
	}
	if action != "" {
		q += " AND action = $3"
		args = append(args, action)
	}
	q += " ORDER BY created_at DESC LIMIT $4 OFFSET $5"
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		s.logger.Error("ListAuditLogs query failed", logger.ErrorField(err))
		return nil, err
	}
	defer rows.Close()
	var out []OrgAuditLog
	for rows.Next() {
		var a OrgAuditLog
		if err := rows.Scan(&a.ID, &a.OrgID, &a.ActorID, &a.Action, &a.TargetID, &a.Details, &a.CreatedAt); err != nil {
			s.logger.Error("ListAuditLogs scan failed", logger.ErrorField(err))
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}
