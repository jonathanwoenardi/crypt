package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
)

var (
	encrypt   = flag.Bool("e", false, "encrypt")
	decrypt   = flag.Bool("d", false, "decrypt")
	input     = flag.String("i", "", "input to be encrypted or decrypted")
	password1 = flag.String("p1", "", "password to be used as encryption key")
	password2 = flag.String("p2", "", "password to be used as encryption key")
)

func main() {
	flag.Parse()
	key := generateKey(*password1, *password2)
	if *encrypt {
		encrypted, err := encryptData(key, []byte(*input))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		encoded := base64.URLEncoding.EncodeToString(encrypted)
		fmt.Println(encoded)
	} else if *decrypt {
		decoded, err := base64.URLEncoding.DecodeString(*input)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		decrypted, err := decryptData(key, []byte(decoded))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Println(string(decrypted))
	}
}

func generateHash(password string) []byte {
	hasher := md5.New()
	hasher.Write([]byte(password))
	return hasher.Sum(nil)
}

func generateKey(password1 string, password2 string) []byte {
	key1 := generateHash(password1)
	key2 := generateHash(password2)
	return append(key1, key2...)
}

func encryptData(key []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func decryptData(key []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
