package docmanagement

import "github.com/graphql-go/graphql"

var ProjectType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Project",
	Fields: graphql.Fields{
		"id":          &graphql.Field{Type: graphql.String},
		"orgId":       &graphql.Field{Type: graphql.String},
		"name":        &graphql.Field{Type: graphql.String},
		"description": &graphql.Field{Type: graphql.String},
		"status":      &graphql.Field{Type: graphql.String},
		"tags":        &graphql.Field{Type: graphql.String},
		"createdAt":   &graphql.Field{Type: graphql.String},
		"updatedAt":   &graphql.Field{Type: graphql.String},
	},
})

func NewProjectFields(resolver ProjectResolver) (graphql.Fields, graphql.Fields) {
	queryFields := graphql.Fields{
		"project": &graphql.Field{
			Type: ProjectType,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				id, _ := p.Args["id"].(string)
				ctx := p.Context
				return resolver.GetProject(ctx, id)
			},
		},
	}

	mutationFields := graphql.Fields{
		"createProject": &graphql.Field{
			Type: ProjectType,
			Args: graphql.FieldConfigArgument{
				"orgId":       &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"name":        &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"description": &graphql.ArgumentConfig{Type: graphql.String},
				"status":      &graphql.ArgumentConfig{Type: graphql.String},
				"tags":        &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				input := map[string]interface{}{
					"orgId":       p.Args["orgId"],
					"name":        p.Args["name"],
					"description": p.Args["description"],
					"status":      p.Args["status"],
					"tags":        p.Args["tags"],
				}
				return resolver.CreateProject(ctx, input)
			},
		},
		"updateProject": &graphql.Field{
			Type: ProjectType,
			Args: graphql.FieldConfigArgument{
				"id":          &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"orgId":       &graphql.ArgumentConfig{Type: graphql.String},
				"name":        &graphql.ArgumentConfig{Type: graphql.String},
				"description": &graphql.ArgumentConfig{Type: graphql.String},
				"status":      &graphql.ArgumentConfig{Type: graphql.String},
				"tags":        &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				id := p.Args["id"].(string)
				input := map[string]interface{}{
					"orgId":       p.Args["orgId"],
					"name":        p.Args["name"],
					"description": p.Args["description"],
					"status":      p.Args["status"],
					"tags":        p.Args["tags"],
				}
				return resolver.UpdateProject(ctx, id, input)
			},
		},
		"deleteProject": &graphql.Field{
			Type: graphql.Boolean,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				id := p.Args["id"].(string)
				return resolver.DeleteProject(ctx, id)
			},
		},
	}

	return queryFields, mutationFields
}
