package docmanagement

import "github.com/graphql-go/graphql"

var CreditType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Credit",
	Fields: graphql.Fields{
		"id":        &graphql.Field{Type: graphql.String},
		"userId":    &graphql.Field{Type: graphql.String},
		"amount":    &graphql.Field{Type: graphql.Float},
		"reason":    &graphql.Field{Type: graphql.String},
		"createdAt": &graphql.Field{Type: graphql.String},
		"updatedAt": &graphql.Field{Type: graphql.String},
	},
})

func NewCreditFields(resolver CreditResolver) (graphql.Fields, graphql.Fields) {
	queryFields := graphql.Fields{
		"credit": &graphql.Field{
			Type: CreditType,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				id, _ := p.Args["id"].(string)
				ctx := p.Context
				return resolver.GetCredit(ctx, id)
			},
		},
	}

	mutationFields := graphql.Fields{
		"createCredit": &graphql.Field{
			Type: CreditType,
			Args: graphql.FieldConfigArgument{
				"userId": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"amount": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.Float)},
				"reason": &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				input := map[string]interface{}{
					"userId": p.Args["userId"],
					"amount": p.Args["amount"],
					"reason": p.Args["reason"],
				}
				return resolver.CreateCredit(ctx, input)
			},
		},
		"updateCredit": &graphql.Field{
			Type: CreditType,
			Args: graphql.FieldConfigArgument{
				"id":     &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"amount": &graphql.ArgumentConfig{Type: graphql.Float},
				"reason": &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				id := p.Args["id"].(string)
				input := map[string]interface{}{
					"amount": p.Args["amount"],
					"reason": p.Args["reason"],
				}
				return resolver.UpdateCredit(ctx, id, input)
			},
		},
		"deleteCredit": &graphql.Field{
			Type: graphql.Boolean,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				id := p.Args["id"].(string)
				return resolver.DeleteCredit(ctx, id)
			},
		},
	}

	return queryFields, mutationFields
}
