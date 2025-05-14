package docmanagement

import (
	"github.com/graphql-go/graphql"
	billing_management "github.com/subinc/subinc-backend/internal/admin/billing-management"
)

var AccountType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Account",
	Fields: graphql.Fields{
		"id":        &graphql.Field{Type: graphql.String},
		"tenantId":  &graphql.Field{Type: graphql.String},
		"email":     &graphql.Field{Type: graphql.String},
		"status":    &graphql.Field{Type: graphql.String},
		"currency":  &graphql.Field{Type: graphql.String},
		"createdAt": &graphql.Field{Type: graphql.String},
		"updatedAt": &graphql.Field{Type: graphql.String},
	},
})

func NewAccountFields(resolver BillingResolver) (graphql.Fields, graphql.Fields) {
	queryFields := graphql.Fields{
		"account": &graphql.Field{
			Type: AccountType,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				id, _ := p.Args["id"].(string)
				ctx := p.Context
				return resolver.GetAccount(ctx, id)
			},
		},
	}

	mutationFields := graphql.Fields{
		"createAccount": &graphql.Field{
			Type: AccountType,
			Args: graphql.FieldConfigArgument{
				"tenantId": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"email":    &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"status":   &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"currency": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				input := billing_management.Account{
					TenantID: p.Args["tenantId"].(string),
					Email:    p.Args["email"].(string),
					Status:   p.Args["status"].(string),
					Currency: p.Args["currency"].(string),
				}
				return resolver.CreateAccount(ctx, input)
			},
		},
	}

	return queryFields, mutationFields
}
