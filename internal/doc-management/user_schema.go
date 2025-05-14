package docmanagement

import (
	"github.com/graphql-go/graphql"
)

var UserType = graphql.NewObject(graphql.ObjectConfig{
	Name: "User",
	Fields: graphql.Fields{
		"id":        &graphql.Field{Type: graphql.String},
		"email":     &graphql.Field{Type: graphql.String},
		"status":    &graphql.Field{Type: graphql.String},
		"createdAt": &graphql.Field{Type: graphql.String},
		"updatedAt": &graphql.Field{Type: graphql.String},
	},
})

func NewUserFields(resolver UserResolver) (graphql.Fields, graphql.Fields) {
	queryFields := graphql.Fields{
		"user": &graphql.Field{
			Type: UserType,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				id, _ := p.Args["id"].(string)
				ctx := p.Context
				return resolver.GetUser(ctx, id)
			},
		},
	}

	mutationFields := graphql.Fields{
		"createUser": &graphql.Field{
			Type: UserType,
			Args: graphql.FieldConfigArgument{
				"email":    &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"password": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				input := User{
					Email: p.Args["email"].(string),
					// Password is not stored here; handle in resolver if needed
				}
				return resolver.CreateUser(ctx, input)
			},
		},
	}

	return queryFields, mutationFields
}
