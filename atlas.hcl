env "local" {
  src = [
    "file://schema.hcl"
  ]
  url = "postgres://postgres:postgres@localhost:5432/subinc?sslmode=disable"
  # dev = "docker://postgres/15/dev?search_path=public"

}


