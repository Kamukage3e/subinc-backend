package docmanagement

import "github.com/graphql-go/graphql"

var OrganizationType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Organization",
	Fields: graphql.Fields{
		"id":        &graphql.Field{Type: graphql.String},
		"name":      &graphql.Field{Type: graphql.String},
		"slug":      &graphql.Field{Type: graphql.String},
		"ownerId":   &graphql.Field{Type: graphql.String},
		"status":    &graphql.Field{Type: graphql.String},
		"createdAt": &graphql.Field{Type: graphql.String},
		"updatedAt": &graphql.Field{Type: graphql.String},
	},
})

func NewOrganizationFields(resolver OrganizationResolver) (graphql.Fields, graphql.Fields) {
	queryFields := graphql.Fields{
		"organization": &graphql.Field{
			Type: OrganizationType,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				id, _ := p.Args["id"].(string)
				ctx := p.Context
				return resolver.GetOrganization(ctx, id)
			},
		},
	}

	mutationFields := graphql.Fields{
		"createOrganization": &graphql.Field{
			Type: OrganizationType,
			Args: graphql.FieldConfigArgument{
				"name":    &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"slug":    &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"ownerId": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"status":  &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				input := map[string]interface{}{
					"name":    p.Args["name"],
					"slug":    p.Args["slug"],
					"ownerId": p.Args["ownerId"],
					"status":  p.Args["status"],
				}
				return resolver.CreateOrganization(ctx, input)
			},
		},
		"updateOrganization": &graphql.Field{
			Type: OrganizationType,
			Args: graphql.FieldConfigArgument{
				"id":      &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"name":    &graphql.ArgumentConfig{Type: graphql.String},
				"slug":    &graphql.ArgumentConfig{Type: graphql.String},
				"ownerId": &graphql.ArgumentConfig{Type: graphql.String},
				"status":  &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				id := p.Args["id"].(string)
				input := map[string]interface{}{
					"name":    p.Args["name"],
					"slug":    p.Args["slug"],
					"ownerId": p.Args["ownerId"],
					"status":  p.Args["status"],
				}
				return resolver.UpdateOrganization(ctx, id, input)
			},
		},
		"deleteOrganization": &graphql.Field{
			Type: graphql.Boolean,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				id := p.Args["id"].(string)
				return resolver.DeleteOrganization(ctx, id)
			},
		},
	}

	return queryFields, mutationFields
}
