package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/subinc/subinc-backend/internal/pkg/commonutil"
	"github.com/subinc/subinc-backend/internal/pkg/logger"
)

// IDHashingConfig represents configuration for the ID hashing middleware
type IDHashingConfig struct {
	// Secret is the HMAC secret for ID hashing
	Secret string
	// Salt adds additional entropy to the hashing process
	Salt string
	// Prefix is prepended to hashed IDs for identification
	Prefix string
	// Logger for error reporting
	Logger *logger.Logger
	// FieldsToObfuscate is a list of JSON fields to obfuscate in responses
	FieldsToObfuscate []string
	// PathsToSkip lists URL paths to skip processing
	PathsToSkip []string
	// IdRegexPatterns lists regex patterns that identify IDs to hash in URL paths
	IdRegexPatterns []*regexp.Regexp
	// ResponseHashingEnabled toggles response body processing
	ResponseHashingEnabled bool
	// RequestHashingEnabled toggles request parameter processing
	RequestHashingEnabled bool
}

// newDefaultIDHashingConfig returns a default configuration
func newDefaultIDHashingConfig() IDHashingConfig {
	return IDHashingConfig{
		Secret:                 "change-me-in-production", // Should be overridden in production
		Salt:                   "subinc-api-salt",         // Should be overridden in production
		Prefix:                 "api",
		Logger:                 logger.Default,
		FieldsToObfuscate:      []string{"id", "uuid", "_id"},
		PathsToSkip:            []string{"/health", "/metrics", "/static"},
		ResponseHashingEnabled: true,
		RequestHashingEnabled:  true,
		IdRegexPatterns: []*regexp.Regexp{
			regexp.MustCompile(`/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)`), // UUID pattern
			regexp.MustCompile(`/([0-9]+)(?:/|$)`),                                                       // Numeric ID pattern
		},
	}
}

// IDHashingMiddleware creates middleware that hashes IDs in URLs and response bodies
func IDHashingMiddleware(config ...IDHashingConfig) fiber.Handler {
	// Use provided config or default
	cfg := newDefaultIDHashingConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	// Create ID hasher
	idHasher := commonutil.NewIDHasher(cfg.Secret, cfg.Salt, cfg.Prefix)

	// Compile the ID pattern if needed (we already have precompiled ones in config)
	return func(c *fiber.Ctx) error {
		// Skip processing for certain paths
		path := c.Path()
		for _, skipPath := range cfg.PathsToSkip {
			if strings.HasPrefix(path, skipPath) {
				return c.Next()
			}
		}

		// Process request parameters if enabled
		if cfg.RequestHashingEnabled {
			// Extract raw ID parameters from URL and replace with their original values
			// This is for URLs like /api/users/:userId where userId might be a hashed ID
			for _, param := range c.Route().Params {
				paramValue := c.Params(param)
				if paramValue != "" && strings.Contains(param, "id") {
					// Try to extract original ID from the hashed value
					originalID := idHasher.ExtractID(paramValue)
					if originalID != "" {
						// Replace in context
						c.Params(param, originalID)
					}
				}
			}
		}

		// Process query parameters (same logic as above)
		queryParams := c.Request().URI().QueryString()
		if len(queryParams) > 0 {
			// TODO: Implement query parameter processing for ID fields
			// This would need to parse the query, extract ID fields, and replace
			// with original values similar to the URL params above
		}

		// Hijack the response to process outgoing data if enabled
		if cfg.ResponseHashingEnabled {
			// Continue with the request
			err := c.Next()
			if err != nil {
				return err
			}

			// Get response body
			responseBody := c.Response().Body()

			// Only process JSON responses
			contentType := string(c.Response().Header.ContentType())
			if strings.Contains(contentType, "application/json") {
				// Try to parse and modify the response
				var responseData interface{}
				if err := json.Unmarshal(responseBody, &responseData); err == nil {
					// Process the response data recursively
					modifiedData := processJSONData(responseData, idHasher, cfg.FieldsToObfuscate)

					// Marshal the modified data
					if modifiedJSON, err := json.Marshal(modifiedData); err == nil {
						// Replace the response body
						c.Response().SetBody(modifiedJSON)
						return nil
					} else {
						// Log error but continue with original response
						if cfg.Logger != nil {
							cfg.Logger.Error("Error marshaling modified response", logger.ErrorField(err))
						}
					}
				} else {
					// Log error but continue with original response
					if cfg.Logger != nil {
						cfg.Logger.Error("Error unmarshaling response for ID obfuscation", logger.ErrorField(err))
					}
				}
			}

			return nil
		}

		return c.Next()
	}
}

// processJSONData recursively processes JSON data to hash ID fields
func processJSONData(data interface{}, hasher *commonutil.IDHasher, fieldsToObfuscate []string) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		// Process each key in the map
		for key, value := range v {
			// Check if this is an ID field that should be obfuscated
			shouldObfuscate := false
			for _, field := range fieldsToObfuscate {
				if strings.HasSuffix(strings.ToLower(key), strings.ToLower(field)) {
					shouldObfuscate = true
					break
				}
			}

			if shouldObfuscate {
				// Handle different ID types
				switch idVal := value.(type) {
				case string:
					// Only hash non-empty values
					if idVal != "" {
						v[key] = hasher.HashID(idVal)
					}
				case float64:
					// For numeric IDs
					v[key] = hasher.HashID(fmt.Sprintf("%.0f", idVal))
				case int, int64:
					// For integer IDs
					v[key] = hasher.HashID(fmt.Sprintf("%v", idVal))
				default:
					// Process nested objects recursively
					v[key] = processJSONData(value, hasher, fieldsToObfuscate)
				}
			} else {
				// Process nested objects recursively
				v[key] = processJSONData(value, hasher, fieldsToObfuscate)
			}
		}
		return v
	case []interface{}:
		// Process each item in the array
		for i, item := range v {
			v[i] = processJSONData(item, hasher, fieldsToObfuscate)
		}
		return v
	default:
		// Return primitive values as is
		return v
	}
}

// responseBodyWriter is a custom io.Writer that captures response data for ID hashing
type responseBodyWriter struct {
	buffer bytes.Buffer
	writer io.Writer
	hasher *commonutil.IDHasher
	fields []string
	logger *logger.Logger
}

func (w *responseBodyWriter) Write(data []byte) (int, error) {
	// Write to the buffer for processing
	n, err := w.buffer.Write(data)
	if err != nil {
		return n, err
	}

	return n, nil
}

// flush processes the buffer and writes to the original writer
func (w *responseBodyWriter) flush() (int, error) {
	data := w.buffer.Bytes()

	// Try to process as JSON if not empty
	if len(data) > 0 {
		var jsonData interface{}
		if err := json.Unmarshal(data, &jsonData); err == nil {
			// Process ID fields
			processed := processJSONData(jsonData, w.hasher, w.fields)

			// Marshal back to JSON
			if processedData, err := json.Marshal(processed); err == nil {
				// Write processed data
				return w.writer.Write(processedData)
			} else {
				if w.logger != nil {
					w.logger.Error("Error marshaling processed response", logger.ErrorField(err))
				}
			}
		} else {
			if w.logger != nil {
				w.logger.Error("Error unmarshaling response for processing", logger.ErrorField(err))
			}
		}
	}

	// Fall back to original data if processing failed
	return w.writer.Write(data)
}
