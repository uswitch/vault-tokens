package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	vault "github.com/hashicorp/vault/api"
)

var (
	vaultServer = os.Getenv("VAULT_SERVER")
	vaultToken  = os.Getenv("VAULT_TOKEN")
	vaultCaPath = os.Getenv("VAULT_CAPATH")
)

type userDetails struct {
	Name string `json:"name"`
}

func main() {

	if vaultServer == "" || vaultToken == "" || vaultCaPath == "" {
		fmt.Println("You need to supply both VAULT_TOKEN and VAULT_SERVER and VAULT_CAPATH")
		os.Exit(1)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			fmt.Fprint(w, "Method not allowed")
			return
		}

		bodyBytes, err := ioutil.ReadAll(r.Body)
		defer r.Body.Close()

		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(w, "Failed to read body: %s", err)
			return
		}
		var body userDetails
		err = json.Unmarshal(bodyBytes, &body)

		if err != nil {
			w.WriteHeader(400)
			fmt.Fprintf(w, "Failed to parse body: %s", err)
			return
		}

		vaultClient, err := newVaultClient(vaultServer, vaultCaPath)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(w, "Failed to create vault client: %s", err)
			return
		}
		token, err := generateToken(vaultClient, body)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(w, "Failed to get token: %s", err)
			return
		}

		var binBuf bytes.Buffer
		resp, err := json.Marshal(token)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(w, "Failed to get parse vault reponse: %s", err)
			return
		}

		binary.Write(&binBuf, binary.BigEndian, resp)
		w.Write(binBuf.Bytes())

	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func generateToken(client *vault.Client, user userDetails) (*vault.Secret, error) {
	auth := client.Auth()
	tokenAuth := auth.Token()
	secret, err := tokenAuth.Create(&vault.TokenCreateRequest{})
	if err != nil {
		return &vault.Secret{}, err
	}
	return secret, nil
}

func newVaultClient(server string, ca string) (*vault.Client, error) {
	config := &vault.Config{
		Address: vaultServer,
	}
	config.ConfigureTLS(&vault.TLSConfig{
		CAPath: ca,
	})
	client, err := vault.NewClient(config)
	if err != nil {
		return &vault.Client{}, err
	}
	return client, nil
}
