package docmanagement

import "github.com/graphql-go/graphql"

var PaymentType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Payment",
	Fields: graphql.Fields{
		"id":        &graphql.Field{Type: graphql.String},
		"invoiceId": &graphql.Field{Type: graphql.String},
		"amount":    &graphql.Field{Type: graphql.Float},
		"currency":  &graphql.Field{Type: graphql.String},
		"status":    &graphql.Field{Type: graphql.String},
		"method":    &graphql.Field{Type: graphql.String},
		"createdAt": &graphql.Field{Type: graphql.String},
		"updatedAt": &graphql.Field{Type: graphql.String},
	},
})

func NewPaymentFields(resolver PaymentResolver) (graphql.Fields, graphql.Fields) {
	queryFields := graphql.Fields{
		"payment": &graphql.Field{
			Type: PaymentType,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				id, _ := p.Args["id"].(string)
				ctx := p.Context
				return resolver.GetPayment(ctx, id)
			},
		},
	}

	mutationFields := graphql.Fields{
		"createPayment": &graphql.Field{
			Type: PaymentType,
			Args: graphql.FieldConfigArgument{
				"invoiceId": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"amount":    &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.Float)},
				"currency":  &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"status":    &graphql.ArgumentConfig{Type: graphql.String},
				"method":    &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				input := map[string]interface{}{
					"invoiceId": p.Args["invoiceId"],
					"amount":    p.Args["amount"],
					"currency":  p.Args["currency"],
					"status":    p.Args["status"],
					"method":    p.Args["method"],
				}
				return resolver.CreatePayment(ctx, input)
			},
		},
		"updatePayment": &graphql.Field{
			Type: PaymentType,
			Args: graphql.FieldConfigArgument{
				"id":        &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"invoiceId": &graphql.ArgumentConfig{Type: graphql.String},
				"amount":    &graphql.ArgumentConfig{Type: graphql.Float},
				"currency":  &graphql.ArgumentConfig{Type: graphql.String},
				"status":    &graphql.ArgumentConfig{Type: graphql.String},
				"method":    &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				id := p.Args["id"].(string)
				input := map[string]interface{}{
					"invoiceId": p.Args["invoiceId"],
					"amount":    p.Args["amount"],
					"currency":  p.Args["currency"],
					"status":    p.Args["status"],
					"method":    p.Args["method"],
				}
				return resolver.UpdatePayment(ctx, id, input)
			},
		},
		"deletePayment": &graphql.Field{
			Type: graphql.Boolean,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				id := p.Args["id"].(string)
				return resolver.DeletePayment(ctx, id)
			},
		},
	}

	return queryFields, mutationFields
}
