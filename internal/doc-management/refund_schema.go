package docmanagement

import "github.com/graphql-go/graphql"

var RefundType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Refund",
	Fields: graphql.Fields{
		"id":          &graphql.Field{Type: graphql.String},
		"paymentId":   &graphql.Field{Type: graphql.String},
		"amount":      &graphql.Field{Type: graphql.Float},
		"reason":      &graphql.Field{Type: graphql.String},
		"status":      &graphql.Field{Type: graphql.String},
		"createdAt":   &graphql.Field{Type: graphql.String},
		"processedAt": &graphql.Field{Type: graphql.String},
	},
})

func NewRefundFields(resolver RefundResolver) (graphql.Fields, graphql.Fields) {
	queryFields := graphql.Fields{
		"refund": &graphql.Field{
			Type: RefundType,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				id, _ := p.Args["id"].(string)
				ctx := p.Context
				return resolver.GetRefund(ctx, id)
			},
		},
	}

	mutationFields := graphql.Fields{
		"createRefund": &graphql.Field{
			Type: RefundType,
			Args: graphql.FieldConfigArgument{
				"paymentId": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"amount":    &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.Float)},
				"reason":    &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				input := map[string]interface{}{
					"paymentId": p.Args["paymentId"],
					"amount":    p.Args["amount"],
					"reason":    p.Args["reason"],
				}
				return resolver.CreateRefund(ctx, input)
			},
		},
		"updateRefund": &graphql.Field{
			Type: RefundType,
			Args: graphql.FieldConfigArgument{
				"id":     &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"amount": &graphql.ArgumentConfig{Type: graphql.Float},
				"reason": &graphql.ArgumentConfig{Type: graphql.String},
				"status": &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				id := p.Args["id"].(string)
				input := map[string]interface{}{
					"amount": p.Args["amount"],
					"reason": p.Args["reason"],
					"status": p.Args["status"],
				}
				return resolver.UpdateRefund(ctx, id, input)
			},
		},
		"deleteRefund": &graphql.Field{
			Type: graphql.Boolean,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				id := p.Args["id"].(string)
				return resolver.DeleteRefund(ctx, id)
			},
		},
	}

	return queryFields, mutationFields
}
