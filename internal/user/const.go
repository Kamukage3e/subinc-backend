package user

// Argon2id password hashing parameters. Chosen for strong security and reasonable performance in SaaS environments.
const (
	argonTime    = 1         // Number of iterations
	argonMemory  = 64 * 1024 // Memory usage in KiB (64 MiB)
	argonThreads = 4         // Number of parallelism threads
	argonKeyLen  = 32        // Length of the generated key in bytes
	argonSaltLen = 16        // Length of the salt in bytes
)
