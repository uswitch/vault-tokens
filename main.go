package main

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

var (
	vaultServer = os.Getenv("VAULT_SERVER")
	vaultToken  = os.Getenv("VAULT_TOKEN")
	vaultCaPath = os.Getenv("VAULT_CAPATH")
	configPath  = os.Getenv("CONFIG_PATH")
)

type userDetails struct {
	Name   string   `json:"name"`
	Groups []string `json:"group"`
}

func main() {

	if vaultServer == "" || vaultToken == "" || vaultCaPath == "" || configPath == "" {
		fmt.Println("You need to supply VAULT_TOKEN, VAULT_SERVER, VAULT_CAPATH and CONFIG_PATH")
		os.Exit(1)
	}

	allowedGroups, err := readConfig(configPath)
	if err != nil {
		fmt.Printf("Could not read csv file: %s", err)
		os.Exit(1)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			fmt.Fprint(w, "Method not allowed")
			return
		}

		//Filter for the groups defined in the config file
		groups, err := filterGroups(r.Header.Get("HTTP_X_FORWARDED_GROUPS"), allowedGroups)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(w, "Failed to parse Groups: %s", err)
			return
		}
		if len(groups) == 0 {
			w.WriteHeader(500)
			fmt.Fprintf(w, "User has no allowed groups")
			return
		}

		user := userDetails{
			Name:   r.Header.Get("HTTP_X_FORWARDED_USER"),
			Groups: groups,
		}

		vaultClient, err := newVaultClient(vaultServer, vaultCaPath)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(w, "Failed to create vault client: %s", err)
			return
		}
		token, err := generateToken(vaultClient, user)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(w, "Failed to get token: %s", err)
			return
		}

		// Return the Vault reponse containing the token
		var binBuf bytes.Buffer
		resp, err := json.Marshal(token)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(w, "Failed to parse vault reponse: %s", err)
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
	secret, err := tokenAuth.Create(&vault.TokenCreateRequest{
		TTL:         "60",
		DisplayName: user.Name,
		Policies:    user.Groups,
	})
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

func readConfig(configPath string) ([]string, error) {
	//Open CSV File
	f, err := os.Open(configPath)
	if err != nil {
		return []string{}, err
	}
	defer f.Close()

	// Read File into a Variable
	allowedGroups, err := csv.NewReader(f).Read()
	if err != nil {
		return []string{}, err
	}

	return allowedGroups, nil
}

func filterGroups(groupString string, allowedGroups []string) ([]string, error) {
	groups := strings.Split(groupString, "|")

	filteredGroups := []string{}

	for _, g := range groups {
		for _, a := range allowedGroups {
			if a == g {
				filteredGroups = append(filteredGroups, a)
			}
		}
	}

	return filteredGroups, nil
}
