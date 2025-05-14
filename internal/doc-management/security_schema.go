package docmanagement

import "github.com/graphql-go/graphql"

var SecurityEventType = graphql.NewObject(graphql.ObjectConfig{
	Name: "SecurityEvent",
	Fields: graphql.Fields{
		"id":        &graphql.Field{Type: graphql.String},
		"userId":    &graphql.Field{Type: graphql.String},
		"eventType": &graphql.Field{Type: graphql.String},
		"details":   &graphql.Field{Type: graphql.String},
		"createdAt": &graphql.Field{Type: graphql.String},
	},
})

func NewSecurityFields(resolver SecurityResolver) (graphql.Fields, graphql.Fields) {
	queryFields := graphql.Fields{
		"securityEvent": &graphql.Field{
			Type: SecurityEventType,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				id, _ := p.Args["id"].(string)
				ctx := p.Context
				return resolver.GetSecurityEvent(ctx, id)
			},
		},
	}

	// No mutation fields for security events in current schema
	mutationFields := graphql.Fields{}

	return queryFields, mutationFields
}
