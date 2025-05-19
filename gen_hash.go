package main; import ("fmt"; "golang.org/x/crypto/bcrypt"); func main() { h, _ := bcrypt.GenerateFromPassword([]byte("falc0nreaper!"), bcrypt.DefaultCost); fmt.Println(string(h)) }
