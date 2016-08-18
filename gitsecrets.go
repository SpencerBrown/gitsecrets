/*
Package gitsecrets provides encryption and decryption of secret files in a Git repository.
Users can check in the encrypted versions of secret files, and securely share them with others.
*/
package gitsecrets

import (
	"github.com/coreos/pkg/cryptoutil"
	"fmt"
	"io/ioutil"
	"bytes"
	"encoding/base64"
	"crypto/rand"
)

// Create a secret key and write it to the specified file. It is written Base64 encoded.
func CreateKey(filename string, keysize int) (error) {

	key, err := randomKey(keysize)
	if err != nil {
		return fmt.Errorf("Error creating key: %v\n", err)
	}

	err = ioutil.WriteFile(filename, []byte(key), 0600)
	if err != nil {
		return fmt.Errorf("Error writing key file %s: %v\n", filename, err)
	}

	return nil
}

// Get the secret key from the specified file, decoding it from Base64.
func GetKey(filename string) ([]byte, error) {

	b64key, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("Error reading key file %s: %v\n", filename, err)
	}

	key, err := base64.StdEncoding.DecodeString(string(b64key))
	if err != nil {
		return nil, fmt.Errorf("Key file contents invalid: %s: %v\n", filename, err)
	}

	return key, nil
}

// Encrypt the specified file, write to a new file whose name has the suffix appended following a dot.
func EncryptFile(filename string, encryptedSuffix string, key []byte) (error) {

	secretData, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("Error reading secret file %s: %v\n", filename, err)
	}

	encryptedData, err := cryptoutil.AESEncrypt(secretData, key)
	if err != nil {
		return fmt.Errorf("Error encrypting data: %v\n", err)
	}

	encryptedFileName := filename + "." + encryptedSuffix
	err = ioutil.WriteFile(encryptedFileName, encryptedData, 0644)
	if err != nil {
		return fmt.Errorf("Error writing new encrypted file %s: %v\n", encryptedFileName, err)
	}

	return nil
}

// Decrypt the specified file, update the secret file if the contents have changed.
// returns true, nil if the contents changed; false, nil if they haven't
func DecryptFile(filename string, encryptedSuffix string, key []byte) (bool, error) {

	encryptedFileName := filename + "." + encryptedSuffix
	encryptedData, err := ioutil.ReadFile(encryptedFileName)
	if err != nil {
		return false, fmt.Errorf("Error reading encrypted file %s: %v\n", encryptedFileName, err)
	}

	secretData, err := cryptoutil.AESDecrypt(encryptedData, key)
	if err != nil {
		return false, fmt.Errorf("Error decrypting data: %v\n", err)
	}

	oldSecretData, err := ioutil.ReadFile(filename)
	if err == nil {
		if bytes.Compare(secretData, oldSecretData) == 0 {
			return false, nil
		}
	}

	// Write the decrypted file unless it exists and matches the decryption of the encrypted file
	err = ioutil.WriteFile(filename, secretData, 0600)
	if err != nil {
		return false, fmt.Errorf("Error writing secret file %s %v\n", filename, err)
	}
	return true, nil
}

// Generates a random key of the specified number of bits.
// Returns a Base64-encoded string.
func randomKey(keysize int) (string, error) {

	if err := checkKeySize(keysize); err != nil {
		return "", err
	}

	out := make([]byte, keysize / 8)
	if _, err := rand.Read(out); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(out), nil
}

// Checks that the key size is a valid AES key size.
func checkKeySize(keysize int) (error) {

	switch keysize {
	case 128:
		return nil
	case 192:
		return nil
	case 256:
		return nil
	default:
		return fmt.Errorf("Invalid key size: %d", keysize)
	}
}