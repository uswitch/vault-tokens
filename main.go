package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	vault "github.com/hashicorp/vault/api"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	vaultServer   = kingpin.Flag("vault-addr", "Vault address, e.g. https://vault:8200").Required().String()
	vaultCaPath   = kingpin.Flag("ca-cert", "Path to CA certificate/certificate folder to validate Vault server").Required().String()
	configPath    = kingpin.Flag("config-path", "Path to config file containing allowed groups").String()
	redirect      = kingpin.Flag("redirect", "redirect responses to http://localhost:63974/authed").Bool()
	kubeLoginPath = kingpin.Flag("login-path", "Path login to vault").Required().String()
	authRole      = kingpin.Flag("role", "Role to get from vault").Required().String()
	tokenRole     = kingpin.Flag("token-role", "Role to use when creating token").String()
)

const (
	redirectToLocalhost = "http://localhost:63974/authed"
)

type userDetails struct {
	Name   string   `json:"name"`
	Groups []string `json:"group"`
}

type login struct {
	JWT  string `json:"jwt"`
	Role string `json:"role"`
}

func main() {

	kingpin.Parse()

	allowedGroups := []string{}

	vaultClient, err := newVaultClient(*vaultServer, *vaultCaPath)
	if err != nil {
		log.Fatalf("Failed to create vault client: %s", err)
		return
	}

	if *configPath != "" {
		var err error
		allowedGroups, err = readConfig(*configPath)
		if err != nil {
			log.Fatalf("Could not read csv file: %s", err)
		}
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		if r.Method != "GET" {
			w.WriteHeader(405)
			fmt.Fprint(w, "Method not allowed")
			return
		}

		//Split the groups into an array
		groups := strings.Split(r.Header.Get("X-FORWARDED-GROUPS"), "|")

		//Filter for the groups defined in the config file
		if len(allowedGroups) != 0 {
			groups = filterGroups(groups, allowedGroups)
			if len(groups) == 0 {
				w.WriteHeader(500)
				fmt.Fprintf(w, "User has no allowed groups")
				return
			}
		}

		user := userDetails{
			Name:   r.Header.Get("X-FORWARDED-USER"),
			Groups: groups,
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

		// if redirect is true will send the token back to the redirect url otherwise it just writes out the token in response
		if *redirect {
			redirectURL, err := url.Parse(redirectToLocalhost)
			if err != nil {
				w.WriteHeader(500)
				fmt.Fprint(w, "Error generating redirect")
				return
			}
			q := redirectURL.Query()
			q.Set("status", "ok")
			q.Set("config", base64.URLEncoding.EncodeToString(binBuf.Bytes()))
			redirectURL.RawQuery = q.Encode()
			http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
		} else {
			w.Write(binBuf.Bytes())
		}

	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func generateToken(client *vault.Client, user userDetails) (*vault.Secret, error) {
	auth := client.Auth()
	tokenAuth := auth.Token()
	renew := false
	secret, err := tokenAuth.CreateWithRole(&vault.TokenCreateRequest{
		TTL:            "12h",
		DisplayName:    user.Name,
		Policies:       user.Groups,
		Renewable:      &renew,
		ExplicitMaxTTL: "12h",
	}, *tokenRole)
	if err != nil {
		return &vault.Secret{}, err
	}
	return secret, nil
}

func newVaultClient(server string, ca string) (*vault.Client, error) {
	config := &vault.Config{
		Address: *vaultServer,
	}
	config.ConfigureTLS(&vault.TLSConfig{
		CAPath: ca,
	})
	client, err := vault.NewClient(config)
	if err != nil {
		return &vault.Client{}, err
	}

	bytes, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("error reading token: %s", err)
	}

	req := client.NewRequest("POST", fmt.Sprintf("/v1/auth/%s", *kubeLoginPath))
	req.SetJSONBody(&login{JWT: string(bytes), Role: *authRole})
	resp, err := client.RawRequest(req)
	if err != nil {
		return nil, err
	}

	if resp.Error() != nil {
		return nil, resp.Error()
	}

	var secret vault.Secret
	err = json.NewDecoder(resp.Body).Decode(&secret)
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %s", err)
	}

	client.SetToken(secret.Auth.ClientToken)

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

func filterGroups(groups, allowedGroups []string) []string {
	filteredGroups := []string{}

	for _, g := range groups {
		for _, a := range allowedGroups {
			if a == g {
				filteredGroups = append(filteredGroups, a)
			}
		}
	}

	return filteredGroups
}
