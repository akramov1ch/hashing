package hashing

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"

	"golang.org/x/crypto/blake2b"
)

func MD5Hash(input string) string {
	hash := md5.Sum([]byte(input))
	return hex.EncodeToString(hash[:])
}

func SHA1Hash(input string) string {
	hash := sha1.Sum([]byte(input))
	return hex.EncodeToString(hash[:])
}

func SHA256Hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

func SHA512Hash(input string) string {
	hash := sha512.Sum512([]byte(input))
	return hex.EncodeToString(hash[:])
}

func BLAKE2bHash(input string) string {
	hash := blake2b.Sum512([]byte(input))
	return hex.EncodeToString(hash[:])
}

func verifyMD5Hash(input string, hash string) bool {
	return MD5Hash(input) == hash
}

func verifySHA1Hash(input string, hash string) bool {
	return SHA1Hash(input) == hash
}

func verifySHA256Hash(input string, hash string) bool {
	return SHA256Hash(input) == hash
}

func verifySHA512Hash(input string, hash string) bool {
	return SHA512Hash(input) == hash
}

func verifyBLAKE2bHash(input string, hash string) bool {
	return BLAKE2bHash(input) == hash
}