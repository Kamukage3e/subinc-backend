package docmanagement

import "github.com/graphql-go/graphql"

var DocumentType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Document",
	Fields: graphql.Fields{
		"id":        &graphql.Field{Type: graphql.String},
		"title":     &graphql.Field{Type: graphql.String},
		"content":   &graphql.Field{Type: graphql.String},
		"ownerId":   &graphql.Field{Type: graphql.String},
		"createdAt": &graphql.Field{Type: graphql.String},
		"updatedAt": &graphql.Field{Type: graphql.String},
	},
})

func NewDocumentFields(resolver DocumentResolver) (graphql.Fields, graphql.Fields) {
	queryFields := graphql.Fields{
		"document": &graphql.Field{
			Type: DocumentType,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				id, _ := p.Args["id"].(string)
				ctx := p.Context
				return resolver.Document(ctx, id)
			},
		},
		"documents": &graphql.Field{
			Type: graphql.NewList(DocumentType),
			Args: graphql.FieldConfigArgument{
				"ownerId": &graphql.ArgumentConfig{Type: graphql.String},
				"title":   &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				filter := DocumentFilter{}
				if v, ok := p.Args["ownerId"].(string); ok {
					filter.OwnerID = &v
				}
				if v, ok := p.Args["title"].(string); ok {
					filter.Title = &v
				}
				return resolver.Documents(ctx, &filter)
			},
		},
	}

	mutationFields := graphql.Fields{
		"createDocument": &graphql.Field{
			Type: DocumentType,
			Args: graphql.FieldConfigArgument{
				"title":   &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"content": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"ownerId": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				input := CreateDocumentInput{
					Title:   p.Args["title"].(string),
					Content: p.Args["content"].(string),
					OwnerID: p.Args["ownerId"].(string),
				}
				return resolver.CreateDocument(ctx, input)
			},
		},
		"updateDocument": &graphql.Field{
			Type: DocumentType,
			Args: graphql.FieldConfigArgument{
				"id":      &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"title":   &graphql.ArgumentConfig{Type: graphql.String},
				"content": &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				id := p.Args["id"].(string)
				input := UpdateDocumentInput{}
				if v, ok := p.Args["title"].(string); ok {
					input.Title = &v
				}
				if v, ok := p.Args["content"].(string); ok {
					input.Content = &v
				}
				return resolver.UpdateDocument(ctx, id, input)
			},
		},
		"deleteDocument": &graphql.Field{
			Type: graphql.Boolean,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				ctx := p.Context
				id := p.Args["id"].(string)
				return resolver.DeleteDocument(ctx, id)
			},
		},
	}

	return queryFields, mutationFields
}
