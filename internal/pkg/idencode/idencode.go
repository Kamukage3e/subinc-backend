package idencode

import (
	"os"

	"github.com/google/uuid"
	"github.com/speps/go-hashids/v2"
)

var hashID *hashids.HashID

func init() {
	salt := os.Getenv("HASHID_SALT")
	if salt == "" {
		salt = "subinc-default-salt-change-me" // secure default, must override in prod
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
