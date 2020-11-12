package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

type Crypto interface {

	/**
	 * Encrypt
	 */
	Encrypt(plaintext []byte) (ciphertext []byte, err error)

	/**
	 * Decrypt
	 */
	Decrypt(ciphertext []byte) (plaintext []byte, err error)

	/**
	 *
	 */
	GetAlgorithm() int32
}

type Plain struct {
}

type AesCrypto struct {
	bit int // 128 192 256
	key string
}

func NewPlain() *Plain {
	return &Plain{}
}

func NewAesCrypto(bit int, key string) *AesCrypto {
	return &AesCrypto{
		bit: bit,
		key: key,
	}
}

func generateKey(key []byte, bit int) (genKey []byte) {
	genKey = make([]byte, bit/8)
	copy(genKey, key)
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			genKey[j] ^= key[i]
		}
	}
	return genKey
}

// CBC
func (aesCrypto *AesCrypto) Encrypt(plaintext []byte) ([]byte, error) {
	key := generateKey([]byte(aesCrypto.key), aesCrypto.bit)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	encryptBytes := pkcs7Padding(plaintext, blockSize)
	encrypted := make([]byte, len(encryptBytes))
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	blockMode.CryptBlocks(encrypted, encryptBytes)
	return encrypted, nil
}

func (aesCrypto *AesCrypto) Decrypt(ciphertext []byte) ([]byte, error) {
	var block cipher.Block
	key := generateKey([]byte(aesCrypto.key), aesCrypto.bit)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	decrypted := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(decrypted, ciphertext)
	decrypted, err = pkcs7UnPadding(decrypted)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

func (aesCrypto *AesCrypto) GetAlgorithm() int32 {
	return 1
}

func (p *Plain) Encrypt(plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

func (p *Plain) Decrypt(ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}

func (p *Plain) GetAlgorithm() int32 {
	return 0
}

func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("encrypted data error")
	}
	unPadding := int(data[length-1])
	return data[:(length - unPadding)], nil
}
