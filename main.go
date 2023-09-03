package main

import (
	"bufio"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	b64 "encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/crewjam/saml/samlsp"
	"golang.org/x/crypto/chacha20poly1305"
)

// really should be pulled from env
const SITE_URL = "http://localhost:12121"

func index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Please use the link the bot sent you to verify your account!")
}

func whoami(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "givenname, %s\n", samlsp.AttributeFromContext(r.Context(), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"))
	fmt.Fprintf(w, "surname, %s\n", samlsp.AttributeFromContext(r.Context(), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"))
	fmt.Fprintf(w, "displayname, %s\n", samlsp.AttributeFromContext(r.Context(), "http://schemas.microsoft.com/identity/claims/displayname"))
	fmt.Fprintf(w, "emailaddress, %s\n", samlsp.AttributeFromContext(r.Context(), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"))
}

var tmpl = template.Must(template.ParseFiles("template.html"))

func verify(w http.ResponseWriter, r *http.Request) {

	uid_b64 := r.URL.Query().Get("t")
	if uid_b64 == "" {
		tmpl.Execute(w, map[string]interface{}{
			"Title":   "Verification failed.",
			"Content": "Incomplete request - please visit the link exactly as it has been sent to you.",
		})
		return
	}
	uid_bytes, err := b64.URLEncoding.DecodeString(uid_b64)
	if err != nil {
		tmpl.Execute(w, map[string]interface{}{
			"Title":   "Verification failed.",
			"Content": "Malformed request - please visit the link exactly as it has been sent to you.",
		})
		return
	}
	// if  len(tokenbytes) != 18 { // I was wrong lol
	// 	fmt.Fprintf(w, "invalid uid")
	// 	return
	// }

	msg := []byte(fmt.Sprintf("{\"userid\":%s, \"givenname\":\"%s\", \"surname\":\"%s\", \"email\":\"%s\", \"expiry\":%d}",
		string(uid_bytes),
		samlsp.AttributeFromContext(r.Context(), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"),
		samlsp.AttributeFromContext(r.Context(), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"),
		samlsp.AttributeFromContext(r.Context(), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"),
		time.Now().Local().Add(5*time.Minute).Unix()))

	fmt.Println(string(msg))

	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(msg)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	encmsg := aead.Seal(nonce, nonce, msg, nil)
	encmsg_b64 := b64.StdEncoding.EncodeToString(encmsg)

	tmpl.Execute(w, map[string]interface{}{
		"Title":   "Please use the following command to complete verification",
		"Content": "!verify " + encmsg_b64,
	})

}

func readKey(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	stats, statsErr := file.Stat()
	if statsErr != nil {
		return nil, statsErr
	}
	var size int64 = stats.Size()
	bytes := make([]byte, size)
	buffer := bufio.NewReader(file)
	_, err = buffer.Read(bytes)
	return bytes, err
}

var aead cipher.AEAD = nil

func main() {
	// initialize AEAD
	keybytes, err := readKey("key_token")
	if err != nil {
		panic(err)
	}
	aead, err = chacha20poly1305.NewX(keybytes)
	if err != nil {
		panic(err)
	}
	// initalize SAML
	keyPair, err := tls.LoadX509KeyPair("key_saml.crt", "key_saml.key")
	if err != nil {
		panic(err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err)
	}

	idpMetadataURL, err := url.Parse("https://login.microsoftonline.com/2b897507-ee8c-4575-830b-4f8267c3d307/federationmetadata/2007-06/federationmetadata.xml") // replace from endpoints
	if err != nil {
		panic(err)
	}
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*idpMetadataURL)
	if err != nil {
		panic(err)
	}
	rootURL, err := url.Parse(SITE_URL)
	if err != nil {
		panic(err)
	}

	samlSP, _ := samlsp.New(samlsp.Options{
		EntityID:    "spn:d7110e78-8dba-4501-a5e1-7f6e54dc7c45",
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
	})

	http.Handle("/saml/", samlSP)
	http.Handle("/verify", samlSP.RequireAccount(http.HandlerFunc(verify)))
	http.Handle("/whoami", samlSP.RequireAccount(http.HandlerFunc(whoami)))
	http.Handle("/", http.HandlerFunc(index))

	fmt.Println("Running...")
	http.ListenAndServe(":12121", nil)
}
