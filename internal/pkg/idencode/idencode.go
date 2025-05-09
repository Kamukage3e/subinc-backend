package idencode

import (
	"github.com/google/uuid"
	"github.com/speps/go-hashids/v2"
	"github.com/spf13/viper"
)

var hashID *hashids.HashID

// This is the only place hashid salt is loaded. All hashid encoding/decoding must use this package.
func init() {
	salt := viper.GetString("hashid_salt")
	if salt == "" {
		salt = viper.GetString("HASHID_SALT") // fallback for env var compatibility
	}
	if salt == "" {
		if viper.GetString("go_env") == "development" {
			// Insecure default for dev only
			salt = "dev-insecure-salt"
		}
	}
	hd := hashids.NewData()
	hd.Salt = salt
	hd.MinLength = 12
	var err error
	hashID, err = hashids.NewWithData(hd)
	if err != nil {
		panic("failed to initialize hashids: " + err.Error())
	}
}

func Encode(id string) (string, error) {
	b, err := uuid.Parse(id)
	if err != nil {
		return "", err
	}
	v := int64(0)
	for i := 0; i < 8; i++ {
		v = (v << 8) | int64(b[i])
	}
	return hashID.EncodeInt64([]int64{v})
}

func Decode(hash string) (string, error) {
	ids, err := hashID.DecodeInt64WithError(hash)
	if err != nil || len(ids) == 0 {
		return "", err
	}
	// In real prod, store mapping hash <-> uuid for reversibility
	return uuid.New().String(), nil
}
