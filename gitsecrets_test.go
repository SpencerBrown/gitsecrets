package gitsecrets

import (
	"fmt"
	"os"
	"testing"
	"io/ioutil"
	"bytes"
	"encoding/base64"
)

const KEY_SIZE = 256

func TestAll(t *testing.T) {

	secretKeyFileName := "secrets-testing.key"
	fileToEncrypt := "hush-testing.txt"
	encryptedSuffix := "encrypted"
	fileEncrypted := fileToEncrypt + "." + encryptedSuffix
	secretData := "Wouldn't want this to get out!"
	err := CreateKey(secretKeyFileName, KEY_SIZE)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("Created %d-bit key, base64-encoded and written to file %s\n", KEY_SIZE, secretKeyFileName)
	key, err := GetKey(secretKeyFileName)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Base64 encoded key is: %s\n", base64.StdEncoding.EncodeToString(key))

	err = ioutil.WriteFile(fileToEncrypt, []byte(secretData), 0600)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Created secret data file %s\n", fileToEncrypt)

	err = EncryptFile(fileToEncrypt, encryptedSuffix, key)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Created encrypted file for %s\n", fileToEncrypt)

	changed, err := DecryptFile(fileToEncrypt, encryptedSuffix, key)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Decrypted file for %s changed=%t\n", fileToEncrypt, changed)
	if changed {
		t.Errorf("Expected false, got true")
	}

	os.Remove(fileToEncrypt)
	changed, err = DecryptFile(fileToEncrypt, encryptedSuffix, key)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Decrypted file for %s changed=%t\n", fileToEncrypt, changed)
	if !changed {
		t.Errorf("Expected true, got false")
	}

	newSecretData, err := ioutil.ReadFile(fileToEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare([]byte(secretData), newSecretData) != 0 {
		t.Errorf("Expected decrypted data to be %q, got %q", secretData, newSecretData)
	}

	os.Remove(secretKeyFileName)
	os.Remove(fileToEncrypt)
	os.Remove(fileEncrypted)
}
