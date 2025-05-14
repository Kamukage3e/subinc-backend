package docmanagement

import "github.com/graphql-go/graphql"

var RBACRoleType = graphql.NewObject(graphql.ObjectConfig{
	Name: "RBACRole",
	Fields: graphql.Fields{
		"id":        &graphql.Field{Type: graphql.String},
		"tenantId":  &graphql.Field{Type: graphql.String},
		"name":      &graphql.Field{Type: graphql.String},
		"desc":      &graphql.Field{Type: graphql.String},
		"createdAt": &graphql.Field{Type: graphql.String},
		"updatedAt": &graphql.Field{Type: graphql.String},
		"deletedAt": &graphql.Field{Type: graphql.String},
	},
})

func NewRBACFields(resolver RBACResolver) (graphql.Fields, graphql.Fields) {
	queryFields := graphql.Fields{
		"rbacRole": &graphql.Field{
			Type: RBACRoleType,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				id, _ := p.Args["id"].(string)
				ctx := p.Context
				return resolver.GetRole(ctx, id)
			},
		},
	}

	mutationFields := graphql.Fields{
		"createRBACRole": &graphql.Field{
			Type: RBACRoleType,
			Args: graphql.FieldConfigArgument{
				"tenantId": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"name":     &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"desc":     &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				input := map[string]interface{}{
					"tenantId": p.Args["tenantId"],
					"name":     p.Args["name"],
					"desc":     p.Args["desc"],
				}
				return resolver.CreateRole(ctx, input)
			},
		},
		"updateRBACRole": &graphql.Field{
			Type: RBACRoleType,
			Args: graphql.FieldConfigArgument{
				"id":       &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"tenantId": &graphql.ArgumentConfig{Type: graphql.String},
				"name":     &graphql.ArgumentConfig{Type: graphql.String},
				"desc":     &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				id := p.Args["id"].(string)
				input := map[string]interface{}{
					"tenantId": p.Args["tenantId"],
					"name":     p.Args["name"],
					"desc":     p.Args["desc"],
				}
				return resolver.UpdateRole(ctx, id, input)
			},
		},
		"deleteRBACRole": &graphql.Field{
			Type: graphql.Boolean,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				id := p.Args["id"].(string)
				return resolver.DeleteRole(ctx, id)
			},
		},
	}

	return queryFields, mutationFields
}
