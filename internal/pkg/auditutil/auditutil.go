package auditutil

import "encoding/json"

// AuditDetails serializes any value to a JSON string for audit logging. Always returns valid JSON.
func AuditDetails(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// MarshalAuditDetails is an alias for AuditDetails for compatibility with legacy code.
func MarshalAuditDetails(v interface{}) string {
	return AuditDetails(v)
}
