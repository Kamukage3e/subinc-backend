package docmanagement

import "github.com/graphql-go/graphql"

var InvoiceType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Invoice",
	Fields: graphql.Fields{
		"id":        &graphql.Field{Type: graphql.String},
		"accountId": &graphql.Field{Type: graphql.String},
		"amount":    &graphql.Field{Type: graphql.Float},
		"currency":  &graphql.Field{Type: graphql.String},
		"status":    &graphql.Field{Type: graphql.String},
		"dueDate":   &graphql.Field{Type: graphql.String},
		"createdAt": &graphql.Field{Type: graphql.String},
		"updatedAt": &graphql.Field{Type: graphql.String},
	},
})

func NewInvoiceFields(resolver InvoiceResolver) (graphql.Fields, graphql.Fields) {
	queryFields := graphql.Fields{
		"invoice": &graphql.Field{
			Type: InvoiceType,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				id, _ := p.Args["id"].(string)
				ctx := p.Context
				return resolver.GetInvoice(ctx, id)
			},
		},
	}

	mutationFields := graphql.Fields{
		"createInvoice": &graphql.Field{
			Type: InvoiceType,
			Args: graphql.FieldConfigArgument{
				"accountId": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"amount":    &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.Float)},
				"currency":  &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"status":    &graphql.ArgumentConfig{Type: graphql.String},
				"dueDate":   &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				input := map[string]interface{}{
					"accountId": p.Args["accountId"],
					"amount":    p.Args["amount"],
					"currency":  p.Args["currency"],
					"status":    p.Args["status"],
					"dueDate":   p.Args["dueDate"],
				}
				return resolver.CreateInvoice(ctx, input)
			},
		},
		"updateInvoice": &graphql.Field{
			Type: InvoiceType,
			Args: graphql.FieldConfigArgument{
				"id":        &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"accountId": &graphql.ArgumentConfig{Type: graphql.String},
				"amount":    &graphql.ArgumentConfig{Type: graphql.Float},
				"currency":  &graphql.ArgumentConfig{Type: graphql.String},
				"status":    &graphql.ArgumentConfig{Type: graphql.String},
				"dueDate":   &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				id := p.Args["id"].(string)
				input := map[string]interface{}{
					"accountId": p.Args["accountId"],
					"amount":    p.Args["amount"],
					"currency":  p.Args["currency"],
					"status":    p.Args["status"],
					"dueDate":   p.Args["dueDate"],
				}
				return resolver.UpdateInvoice(ctx, id, input)
			},
		},
		"deleteInvoice": &graphql.Field{
			Type: graphql.Boolean,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				id := p.Args["id"].(string)
				return resolver.DeleteInvoice(ctx, id)
			},
		},
	}

	return queryFields, mutationFields
}
