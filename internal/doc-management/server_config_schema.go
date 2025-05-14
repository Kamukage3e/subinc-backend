package docmanagement

import "github.com/graphql-go/graphql"

var ServerConfigType = graphql.NewObject(graphql.ObjectConfig{
	Name: "ServerConfig",
	Fields: graphql.Fields{
		"key":       &graphql.Field{Type: graphql.String},
		"value":     &graphql.Field{Type: graphql.String},
		"version":   &graphql.Field{Type: graphql.Int},
		"updatedAt": &graphql.Field{Type: graphql.String},
	},
})

func NewServerConfigFields(resolver ServerConfigResolver) (graphql.Fields, graphql.Fields) {
	queryFields := graphql.Fields{
		"serverConfig": &graphql.Field{
			Type: ServerConfigType,
			Args: graphql.FieldConfigArgument{
				"key": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				key, _ := p.Args["key"].(string)
				ctx := p.Context
				return resolver.GetConfig(ctx, key)
			},
		},
	}

	mutationFields := graphql.Fields{
		"setServerConfig": &graphql.Field{
			Type: ServerConfigType,
			Args: graphql.FieldConfigArgument{
				"key":   &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"value": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				key := p.Args["key"].(string)
				value := p.Args["value"]
				return resolver.SetConfig(ctx, key, value)
			},
		},
	}

	return queryFields, mutationFields
}
