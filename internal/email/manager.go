package email

import (
	"bytes"
	"fmt"
	"net/smtp"
	"sync"
	"text/template"
	"time"

	. "github.com/subinc/subinc-backend/internal/pkg/logger"
)

// EmailManager implements user.EmailSender and supports dynamic provider config
// This is a real, production-grade, team-managed email backend for SaaS

// ProviderType defines supported email provider types
// Extend with more as needed (e.g., API, SES, Mailgun, etc.)
type ProviderType string

const (
	ProviderSMTP ProviderType = "smtp"
)

type EmailProviderConfig struct {
	Name     string       // Unique name for this provider
	Type     ProviderType // e.g., "smtp"
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// Add more fields as needed for other providers
}

// EmailTemplate represents a dynamic email template
// Templates are stored in-memory, ready for DB extension
type EmailTemplate struct {
	Name    string // unique name
	Subject string
	Body    string // Go text/template syntax
}

// DeliveryStatus represents the delivery status of an email
// Extend for real DB-backed delivery tracking in SaaS
// Status: sent, delivered, bounced, failed, etc.
type DeliveryStatus struct {
	ID        string // message ID
	Recipient string
	Status    string
	Timestamp int64
	Error     string
}

// Conversation represents an email thread/conversation
// Used for full SaaS-grade email conversations (support, marketing, etc.)
type Conversation struct {
	ID           string // unique conversation ID
	Subject      string
	Participants []string // emails
	Messages     []string // message IDs
	CreatedAt    int64
}

// Message represents a single email in a conversation
// Used for full SaaS-grade email conversations
// Status: sent, delivered, bounced, failed, etc.
type Message struct {
	ID             string
	ConversationID string
	From           string
	To             []string
	Body           string
	Timestamp      int64
	Status         string
	Error          string
}

type EmailManager struct {
	log             *Logger
	mu              sync.RWMutex
	providers       map[string]EmailProviderConfig // name -> config
	defaultProvider string                         // default provider name
	templates       map[string]EmailTemplate       // name -> template
	teamAdmins      map[string][]string            // team name -> list of admin emails
	deliveries      []DeliveryStatus               // in-memory deliveries
	conversations   map[string]*Conversation       // conversationID -> Conversation
	messages        map[string]*Message            // messageID -> Message
}

func NewEmailManager(log *Logger) *EmailManager {
	return &EmailManager{
		log:             log,
		providers:       make(map[string]EmailProviderConfig),
		defaultProvider: "",
	}
}

// AddProvider adds or updates a provider config
func (m *EmailManager) AddProvider(cfg EmailProviderConfig, setDefault bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providers[cfg.Name] = cfg
	if setDefault || m.defaultProvider == "" {
		m.defaultProvider = cfg.Name
	}
}

// RemoveProvider deletes a provider config
func (m *EmailManager) RemoveProvider(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.providers, name)
	if m.defaultProvider == name {
		m.defaultProvider = ""
		for n := range m.providers {
			m.defaultProvider = n
			break
		}
	}
}

// ListProviders returns all provider configs
func (m *EmailManager) ListProviders() []EmailProviderConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]EmailProviderConfig, 0, len(m.providers))
	for _, cfg := range m.providers {
		out = append(out, cfg)
	}
	return out
}

// SetDefaultProvider sets the default provider by name
func (m *EmailManager) SetDefaultProvider(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.providers[name]; !ok {
		return fmt.Errorf("provider not found: %s", name)
	}
	m.defaultProvider = name
	return nil
}

// SendResetEmail uses the default provider
func (m *EmailManager) SendResetEmail(to, token string) error {
	return m.SendResetEmailFrom(m.defaultProvider, to, token)
}

// SendVerificationEmail uses the default provider
func (m *EmailManager) SendVerificationEmail(to, token string) error {
	return m.SendVerificationEmailFrom(m.defaultProvider, to, token)
}

// SendResetEmailFrom sends using a specific provider
func (m *EmailManager) SendResetEmailFrom(provider, to, token string) error {
	cfg, err := m.getProvider(provider)
	if err != nil {
		return err
	}
	if cfg.Type == ProviderSMTP {
		return m.sendSMTP(cfg, to, "Password Reset", fmt.Sprintf("Reset your password: https://app.subinc.com/reset?token=%s", token))
	}
	return fmt.Errorf("unsupported email provider type: %s", cfg.Type)
}

// SendVerificationEmailFrom sends using a specific provider
func (m *EmailManager) SendVerificationEmailFrom(provider, to, token string) error {
	cfg, err := m.getProvider(provider)
	if err != nil {
		return err
	}
	if cfg.Type == ProviderSMTP {
		return m.sendSMTP(cfg, to, "Verify Your Email", fmt.Sprintf("Verify your email: https://app.subinc.com/verify?token=%s", token))
	}
	return fmt.Errorf("unsupported email provider type: %s", cfg.Type)
}

func (m *EmailManager) getProvider(name string) (EmailProviderConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cfg, ok := m.providers[name]
	if !ok {
		return EmailProviderConfig{}, fmt.Errorf("email provider not found: %s", name)
	}
	return cfg, nil
}

func (m *EmailManager) sendSMTP(cfg EmailProviderConfig, to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	msg := []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", cfg.From, to, subject, body))
	return smtp.SendMail(addr, auth, cfg.From, []string{to}, msg)
}

// UpdateProvider updates an existing provider config
func (m *EmailManager) UpdateProvider(cfg EmailProviderConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.providers[cfg.Name]; !ok {
		return fmt.Errorf("provider not found: %s", cfg.Name)
	}
	m.providers[cfg.Name] = cfg
	m.log.Info("email provider updated", String("provider", cfg.Name))
	return nil
}

// UpdateSMTPCredentials updates SMTP credentials for a provider
func (m *EmailManager) UpdateSMTPCredentials(name, username, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, ok := m.providers[name]
	if !ok {
		return fmt.Errorf("provider not found: %s", name)
	}
	cfg.Username = username
	cfg.Password = password
	m.providers[name] = cfg
	m.log.Info("smtp credentials updated", String("provider", name))
	return nil
}

// TestSMTPConnection tests SMTP connection for a provider
func (m *EmailManager) TestSMTPConnection(name string) error {
	cfg, err := m.getProvider(name)
	if err != nil {
		return err
	}
	if cfg.Type != ProviderSMTP {
		return fmt.Errorf("not an SMTP provider: %s", name)
	}
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	// Use a NOOP command to test connection (RFC 5321)
	c, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Hello("localhost"); err != nil {
		return err
	}
	if err := c.Auth(auth); err != nil {
		return err
	}
	return nil
}

// AddTemplate adds or updates a template
func (m *EmailManager) AddTemplate(tpl EmailTemplate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.templates == nil {
		m.templates = make(map[string]EmailTemplate)
	}
	m.templates[tpl.Name] = tpl
	m.log.Info("email template added/updated", String("template", tpl.Name))
}

// RemoveTemplate deletes a template
func (m *EmailManager) RemoveTemplate(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.templates, name)
	m.log.Info("email template removed", String("template", name))
}

// ListTemplates returns all templates
func (m *EmailManager) ListTemplates() []EmailTemplate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]EmailTemplate, 0, len(m.templates))
	for _, tpl := range m.templates {
		out = append(out, tpl)
	}
	return out
}

// SendWithTemplate sends an email using a named template and data
func (m *EmailManager) SendWithTemplate(provider, templateName, to string, data any) error {
	tpl, err := m.getTemplate(templateName)
	if err != nil {
		return err
	}
	subj, body, err := renderTemplate(tpl, data)
	if err != nil {
		return err
	}
	cfg, err := m.getProvider(provider)
	if err != nil {
		return err
	}
	if cfg.Type == ProviderSMTP {
		return m.sendSMTP(cfg, to, subj, body)
	}
	return fmt.Errorf("unsupported email provider type: %s", cfg.Type)
}

func (m *EmailManager) getTemplate(name string) (EmailTemplate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tpl, ok := m.templates[name]
	if !ok {
		return EmailTemplate{}, fmt.Errorf("email template not found: %s", name)
	}
	return tpl, nil
}

func renderTemplate(tpl EmailTemplate, data any) (string, string, error) {
	tmpl, err := template.New("subject").Parse(tpl.Subject)
	if err != nil {
		return "", "", err
	}
	var subjBuf bytes.Buffer
	if err := tmpl.Execute(&subjBuf, data); err != nil {
		return "", "", err
	}
	tmpl, err = template.New("body").Parse(tpl.Body)
	if err != nil {
		return "", "", err
	}
	var bodyBuf bytes.Buffer
	if err := tmpl.Execute(&bodyBuf, data); err != nil {
		return "", "", err
	}
	return subjBuf.String(), bodyBuf.String(), nil
}

// AddTeamAdmin adds an admin email to a team (e.g., support, marketing, ssm)
func (m *EmailManager) AddTeamAdmin(team, email string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.teamAdmins == nil {
		m.teamAdmins = make(map[string][]string)
	}
	for _, e := range m.teamAdmins[team] {
		if e == email {
			return // already present
		}
	}
	m.teamAdmins[team] = append(m.teamAdmins[team], email)
	m.log.Info("team admin added", String("team", team), String("email", email))
}

// RemoveTeamAdmin removes an admin email from a team
func (m *EmailManager) RemoveTeamAdmin(team, email string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	admins := m.teamAdmins[team]
	out := admins[:0]
	for _, e := range admins {
		if e != email {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		delete(m.teamAdmins, team)
	} else {
		m.teamAdmins[team] = out
	}
	m.log.Info("team admin removed", String("team", team), String("email", email))
}

// ListTeamAdmins returns all admin emails for a team
func (m *EmailManager) ListTeamAdmins(team string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string(nil), m.teamAdmins[team]...)
}

// SendToTeam sends an email (optionally with template) to all admins of a team
func (m *EmailManager) SendToTeam(team, templateName, subject, body string, data any) error {
	admins := m.ListTeamAdmins(team)
	if len(admins) == 0 {
		return fmt.Errorf("no admins for team: %s", team)
	}
	provider := m.defaultProvider
	if templateName != "" {
		tpl, err := m.getTemplate(templateName)
		if err != nil {
			return err
		}
		subj, b, err := renderTemplate(tpl, data)
		if err != nil {
			return err
		}
		subject = subj
		body = b
	}
	cfg, err := m.getProvider(provider)
	if err != nil {
		return err
	}
	if cfg.Type != ProviderSMTP {
		return fmt.Errorf("unsupported provider type: %s", cfg.Type)
	}
	for _, to := range admins {
		err := m.sendSMTP(cfg, to, subject, body)
		if err != nil {
			m.log.Error("failed to send team email", String("team", team), String("to", to), ErrorField(err))
		}
	}
	return nil
}

// Add methods for dynamic config update, provider switching, etc. as needed

// ListDeliveries returns delivery status for emails (by recipient/status)
func (m *EmailManager) ListDeliveries(recipient, status string, limit, offset int) ([]DeliveryStatus, error) {
	// In-memory stub; replace with DB-backed implementation for prod
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []DeliveryStatus
	for _, d := range m.deliveries {
		if recipient != "" && d.Recipient != recipient {
			continue
		}
		if status != "" && d.Status != status {
			continue
		}
		out = append(out, d)
	}
	if offset > len(out) {
		offset = len(out)
	}
	end := offset + limit
	if end > len(out) {
		end = len(out)
	}
	return out[offset:end], nil
}

// StartConversation creates a new conversation and first message
func (m *EmailManager) StartConversation(subject string, from string, to []string, body string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.conversations == nil {
		m.conversations = make(map[string]*Conversation)
	}
	if m.messages == nil {
		m.messages = make(map[string]*Message)
	}
	cid := generateID()
	mid := generateID()
	conv := &Conversation{
		ID:           cid,
		Subject:      subject,
		Participants: append([]string{from}, to...),
		Messages:     []string{mid},
		CreatedAt:    nowUnix(),
	}
	msg := &Message{
		ID:             mid,
		ConversationID: cid,
		From:           from,
		To:             to,
		Body:           body,
		Timestamp:      nowUnix(),
		Status:         "sent",
	}
	m.conversations[cid] = conv
	m.messages[mid] = msg
	return cid, nil
}

// AddMessage adds a message to an existing conversation
func (m *EmailManager) AddMessage(conversationID, from string, to []string, body string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	conv, ok := m.conversations[conversationID]
	if !ok {
		return "", fmt.Errorf("conversation not found")
	}
	mid := generateID()
	msg := &Message{
		ID:             mid,
		ConversationID: conversationID,
		From:           from,
		To:             to,
		Body:           body,
		Timestamp:      nowUnix(),
		Status:         "sent",
	}
	conv.Messages = append(conv.Messages, mid)
	m.messages[mid] = msg
	return mid, nil
}

// ListConversations returns all conversations for a participant
func (m *EmailManager) ListConversations(participant string) []*Conversation {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*Conversation
	for _, c := range m.conversations {
		for _, p := range c.Participants {
			if p == participant {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// ListMessages returns all messages in a conversation
func (m *EmailManager) ListMessages(conversationID string) []*Message {
	m.mu.RLock()
	defer m.mu.RUnlock()
	conv, ok := m.conversations[conversationID]
	if !ok {
		return nil
	}
	var out []*Message
	for _, mid := range conv.Messages {
		if msg, ok := m.messages[mid]; ok {
			out = append(out, msg)
		}
	}
	return out
}

// generateID returns a pseudo-unique string (replace with UUID in prod)
func generateID() string {
	return fmt.Sprintf("id-%d", nowUnixNano())
}

// nowUnix returns current unix timestamp
func nowUnix() int64 {
	return int64(nowUnixNano() / 1e9)
}

// nowUnixNano returns current unix timestamp in nanoseconds
func nowUnixNano() int64 {
	return time.Now().UnixNano()
}

func (m *EmailManager) SendDeviceLoginNotification(to, deviceName, ip, userAgent string) error {
	cfg, err := m.getProvider(m.defaultProvider)
	if err != nil {
		return err
	}
	subject := "New device login detected"
	body := "A new device has logged into your account.\n\n" +
		"Device: " + deviceName + "\n" +
		"IP: " + ip + "\n" +
		"User Agent: " + userAgent + "\n" +
		"If this was not you, please revoke the device and reset your password immediately."
	if cfg.Type == ProviderSMTP {
		return m.sendSMTP(cfg, to, subject, body)
	}
	return fmt.Errorf("unsupported email provider type: %s", cfg.Type)
}

func (m *EmailManager) SendDeviceChangeNotification(to, deviceName, changeType string) error {
	cfg, err := m.getProvider(m.defaultProvider)
	if err != nil {
		return err
	}
	subject := "Device " + changeType + " notification"
	body := "A device associated with your account was " + changeType + ":\n\n" +
		"Device: " + deviceName + "\n" +
		"If this was not you, please review your account security."
	if cfg.Type == ProviderSMTP {
		return m.sendSMTP(cfg, to, subject, body)
	}
	return fmt.Errorf("unsupported email provider type: %s", cfg.Type)
}
