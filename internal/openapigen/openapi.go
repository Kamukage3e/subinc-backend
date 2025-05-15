package openapigen

import (
	"bytes"

	"gopkg.in/yaml.v3"
)

type OpenAPISpec struct {
	OpenAPI    string              `yaml:"openapi"`
	Info       Info                `yaml:"info"`
	Servers    []Server            `yaml:"servers,omitempty"`
	Paths      map[string]PathItem `yaml:"paths"`
	Components *Components         `yaml:"components,omitempty"`
	Tags       []Tag               `yaml:"tags,omitempty"`
}

type Info struct {
	Title       string   `yaml:"title"`
	Description string   `yaml:"description,omitempty"`
	Version     string   `yaml:"version"`
	Contact     *Contact `yaml:"contact,omitempty"`
	License     *License `yaml:"license,omitempty"`
}

type Contact struct {
	Name  string `yaml:"name,omitempty"`
	URL   string `yaml:"url,omitempty"`
	Email string `yaml:"email,omitempty"`
}

type License struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url,omitempty"`
}

type Server struct {
	URL         string                    `yaml:"url"`
	Description string                    `yaml:"description,omitempty"`
	Variables   map[string]ServerVariable `yaml:"variables,omitempty"`
}

type ServerVariable struct {
	Enum        []string `yaml:"enum,omitempty"`
	Default     string   `yaml:"default"`
	Description string   `yaml:"description,omitempty"`
}

type Tag struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
}

type Components struct {
	Schemas         map[string]Schema         `yaml:"schemas,omitempty"`
	Responses       map[string]Response       `yaml:"responses,omitempty"`
	Parameters      map[string]Parameter      `yaml:"parameters,omitempty"`
	RequestBodies   map[string]RequestBody    `yaml:"requestBodies,omitempty"`
	SecuritySchemes map[string]SecurityScheme `yaml:"securitySchemes,omitempty"`
}

type SecurityScheme struct {
	Type         string `yaml:"type"`
	Description  string `yaml:"description,omitempty"`
	Name         string `yaml:"name,omitempty"`
	In           string `yaml:"in,omitempty"`
	Scheme       string `yaml:"scheme,omitempty"`
	BearerFormat string `yaml:"bearerFormat,omitempty"`
}

type PathItem struct {
	Summary     string      `yaml:"summary,omitempty"`
	Description string      `yaml:"description,omitempty"`
	Get         *Operation  `yaml:"get,omitempty"`
	Post        *Operation  `yaml:"post,omitempty"`
	Put         *Operation  `yaml:"put,omitempty"`
	Delete      *Operation  `yaml:"delete,omitempty"`
	Patch       *Operation  `yaml:"patch,omitempty"`
	Parameters  []Parameter `yaml:"parameters,omitempty"`
}

type Operation struct {
	Summary     string                `yaml:"summary,omitempty"`
	Description string                `yaml:"description,omitempty"`
	OperationID string                `yaml:"operationId,omitempty"`
	Tags        []string              `yaml:"tags,omitempty"`
	Parameters  []Parameter           `yaml:"parameters,omitempty"`
	RequestBody *RequestBody          `yaml:"requestBody,omitempty"`
	Responses   map[string]Response   `yaml:"responses"`
	Security    []map[string][]string `yaml:"security,omitempty"`
	Deprecated  bool                  `yaml:"deprecated,omitempty"`
}

type RequestBody struct {
	Description string               `yaml:"description,omitempty"`
	Required    bool                 `yaml:"required,omitempty"`
	Content     map[string]MediaType `yaml:"content"`
}

type Parameter struct {
	Name            string      `yaml:"name"`
	In              string      `yaml:"in"`
	Description     string      `yaml:"description,omitempty"`
	Required        bool        `yaml:"required"`
	Deprecated      bool        `yaml:"deprecated,omitempty"`
	AllowEmptyValue bool        `yaml:"allowEmptyValue,omitempty"`
	Schema          Schema      `yaml:"schema"`
	Example         interface{} `yaml:"example,omitempty"`
}

type Response struct {
	Description string               `yaml:"description"`
	Content     map[string]MediaType `yaml:"content,omitempty"`
	Headers     map[string]Header    `yaml:"headers,omitempty"`
}

type MediaType struct {
	Schema   Schema             `yaml:"schema"`
	Example  interface{}        `yaml:"example,omitempty"`
	Examples map[string]Example `yaml:"examples,omitempty"`
}

type Example struct {
	Summary       string      `yaml:"summary,omitempty"`
	Description   string      `yaml:"description,omitempty"`
	Value         interface{} `yaml:"value,omitempty"`
	ExternalValue string      `yaml:"externalValue,omitempty"`
}

type Header struct {
	Description string `yaml:"description"`
	Schema      Schema `yaml:"schema"`
}

type Schema struct {
	Type                 string            `yaml:"type,omitempty"`
	Format               string            `yaml:"format,omitempty"`
	Items                *Schema           `yaml:"items,omitempty"`
	Properties           map[string]Schema `yaml:"properties,omitempty"`
	AdditionalProperties interface{}       `yaml:"additionalProperties,omitempty"`
	Required             []string          `yaml:"required,omitempty"`
	Description          string            `yaml:"description,omitempty"`
	Default              interface{}       `yaml:"default,omitempty"`
	Nullable             bool              `yaml:"nullable,omitempty"`
	Enum                 []interface{}     `yaml:"enum,omitempty"`
	Example              interface{}       `yaml:"example,omitempty"`
	Examples             interface{}       `yaml:"examples,omitempty"`
	Ref                  string            `yaml:"$ref,omitempty"`
	MinLength            *int              `yaml:"minLength,omitempty"`
	MaxLength            *int              `yaml:"maxLength,omitempty"`
	Pattern              string            `yaml:"pattern,omitempty"`
	Minimum              *float64          `yaml:"minimum,omitempty"`
	Maximum              *float64          `yaml:"maximum,omitempty"`
	ExclusiveMinimum     bool              `yaml:"exclusiveMinimum,omitempty"`
	ExclusiveMaximum     bool              `yaml:"exclusiveMaximum,omitempty"`
	MultipleOf           *float64          `yaml:"multipleOf,omitempty"`
	MinItems             *int              `yaml:"minItems,omitempty"`
	MaxItems             *int              `yaml:"maxItems,omitempty"`
	UniqueItems          bool              `yaml:"uniqueItems,omitempty"`
	Deprecated           bool              `yaml:"deprecated,omitempty"`
	ReadOnly             bool              `yaml:"readOnly,omitempty"`
	WriteOnly            bool              `yaml:"writeOnly,omitempty"`
}

func MarshalOpenAPI(spec OpenAPISpec) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(spec); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
