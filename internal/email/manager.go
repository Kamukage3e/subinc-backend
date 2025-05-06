package email

import (
	"bytes"
	"fmt"
	"net/smtp"
	"sync"
	"text/template"

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

type EmailManager struct {
	log             *Logger
	mu              sync.RWMutex
	providers       map[string]EmailProviderConfig // name -> config
	defaultProvider string                         // default provider name
	templates       map[string]EmailTemplate       // name -> template
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

// Add methods for dynamic config update, provider switching, etc. as needed
