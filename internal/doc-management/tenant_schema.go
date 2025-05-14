package docmanagement

import (
	"github.com/graphql-go/graphql"
	tenant_management "github.com/subinc/subinc-backend/internal/admin/tenant-management"
)

var TenantType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Tenant",
	Fields: graphql.Fields{
		"id":        &graphql.Field{Type: graphql.String},
		"name":      &graphql.Field{Type: graphql.String},
		"status":    &graphql.Field{Type: graphql.String},
		"settings":  &graphql.Field{Type: graphql.String},
		"createdAt": &graphql.Field{Type: graphql.String},
		"updatedAt": &graphql.Field{Type: graphql.String},
	},
})

func NewTenantFields(resolver TenantResolver) (graphql.Fields, graphql.Fields) {
	queryFields := graphql.Fields{
		"tenant": &graphql.Field{
			Type: TenantType,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				id, _ := p.Args["id"].(string)
				ctx := p.Context
				return resolver.GetTenant(ctx, id)
			},
		},
	}

	mutationFields := graphql.Fields{
		"createTenant": &graphql.Field{
			Type: TenantType,
			Args: graphql.FieldConfigArgument{
				"name":     &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"status":   &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"settings": &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				input := tenant_management.Tenant{
					Name:     p.Args["name"].(string),
					Status:   tenant_management.TenantStatus(p.Args["status"].(string)),
					Settings: p.Args["settings"].(string),
				}
				return resolver.CreateTenant(ctx, input)
			},
		},
		"updateTenant": &graphql.Field{
			Type: TenantType,
			Args: graphql.FieldConfigArgument{
				"id":       &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"name":     &graphql.ArgumentConfig{Type: graphql.String},
				"status":   &graphql.ArgumentConfig{Type: graphql.String},
				"settings": &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				input := tenant_management.Tenant{
					ID:       p.Args["id"].(string),
					Name:     p.Args["name"].(string),
					Status:   tenant_management.TenantStatus(p.Args["status"].(string)),
					Settings: p.Args["settings"].(string),
				}
				return resolver.UpdateTenant(ctx, input)
			},
		},
		"deleteTenant": &graphql.Field{
			Type: graphql.Boolean,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				id := p.Args["id"].(string)
				return resolver.DeleteTenant(ctx, id)
			},
		},
	}

	return queryFields, mutationFields
}
