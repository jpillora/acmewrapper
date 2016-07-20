package acmewrapper

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCert(t *testing.T) {
	os.Remove("cert.crt")
	os.Remove("key.pem")

	w, err := New(Config{
		Server:           TESTAPI,
		TOSCallback:      TOSAgree,
		Domains:          TESTDOMAINS,
		PrivateKeyFile:   "testinguser.key",
		RegistrationFile: "testinguser.reg",
		Address:          TLSADDRESS,

		TLSCertFile: "cert.crt",
		TLSKeyFile:  "key.pem",
	})

	require.NoError(t, err)

	c := w.GetCertificate().Certificate[0]

	// Make sure the files were written
	_, err = os.Stat("cert.crt")
	require.False(t, os.IsNotExist(err))
	_, err = os.Stat("key.pem")
	require.False(t, os.IsNotExist(err))

	// Make sure that the key and cert were generated correctly - make the TOS fail,
	// and the renew callback fail, since ACME shouldn't need to be set at all
	hadfailure := false
	w, err = New(Config{
		Server:           TESTAPI,
		TOSCallback:      TOSDecline,
		Domains:          TESTDOMAINS,
		PrivateKeyFile:   "testinguser.key",
		RegistrationFile: "testinguser.reg",
		Address:          TLSADDRESS,

		TLSCertFile: "cert.crt",
		TLSKeyFile:  "key.pem",

		RenewCallback: func() {
			hadfailure = true
		},
	})

	require.NoError(t, err)
	require.False(t, hadfailure)
	require.True(t, bytes.Equal(w.GetCertificate().Certificate[0], c))

	// Now make sure that we can load without ACME enabled using our currentkeys
	w, err = New(Config{
		Server:       TESTAPI,
		AcmeDisabled: true,

		TLSCertFile: "cert.crt",
		TLSKeyFile:  "key.pem",
	})

	require.NoError(t, err)
	require.False(t, hadfailure)
	require.True(t, bytes.Equal(w.GetCertificate().Certificate[0], c))

	// Lastly: Make sure we can start without ACME enabled, but enable it later.
	// NOTE: This also tests our renewal function
	renewnum := 0
	w, err = New(Config{
		AcmeDisabled: true,
		Server:       TESTAPI,
		TOSCallback:  TOSAgree,
		Domains:      TESTDOMAINS,
		Address:      TLSADDRESS,

		TLSCertFile: "cert.crt",
		TLSKeyFile:  "key.pem",

		RenewCallback: func() {
			renewnum++
		},

		RenewTime:  50 * 365 * 24 * time.Hour, // A ridiculous value so that renew always happens
		RenewCheck: 3 * time.Second,
		RetryDelay: 3 * time.Second,

		RenewFailedCallback: func(err error) {
			require.NoError(t, err)
		},
	})

	require.NoError(t, err)

	// Now start a server with the config
	listener, err := tls.Listen("tcp", TLSADDRESS, w.TLSConfig())
	require.NoError(t, err)
	go func() {
		http.Serve(listener, nil)
	}()

	fmt.Printf("acmeenable\n")
	require.NoError(t, w.AcmeDisabled(false))

	// Now the certificate should be set
	fmt.Printf("getcert\n")
	crt := w.GetCertificate()
	fmt.Printf("Sleeping for 8 seconds...\n")
	time.Sleep(8 * time.Second)
	fmt.Printf("Done sleeping\n")

	// The certificate should be renewed
	require.NotEqual(t, crt, w.GetCertificate())
	require.True(t, renewnum >= 2)

	// Stop it from being annoying in the background anymore
	w.Config.RenewCheck = 9999 * 24 * time.Hour
	w.Config.RetryDelay = 9999 * 24 * time.Hour
	w.Config.RenewTime = 30 * time.Hour
	listener.Close()
}

// We now test to make sure that if the domain is changed,
// the cert is changed
func TestDomainChange(t *testing.T) {
	os.Remove("cert.crt")
	os.Remove("key.pem")
	newdomains := []string{"www." + TESTDOMAINS[0], TESTDOMAINS[0]}

	domainchanged := false

	// First set up the domain cert
	_, err := New(Config{
		Server:           TESTAPI,
		TOSCallback:      TOSAgree,
		Domains:          TESTDOMAINS,
		PrivateKeyFile:   "testinguser.key",
		RegistrationFile: "testinguser.reg",
		Address:          TLSADDRESS,

		TLSCertFile: "cert.crt",
		TLSKeyFile:  "key.pem",

		RenewCallback: func() {
			domainchanged = true
		},
	})

	require.NoError(t, err)
	require.True(t, domainchanged)

	// Now running again will not renew
	domainchanged = false
	// First set up the domain cert
	_, err = New(Config{
		Server:           TESTAPI,
		TOSCallback:      TOSAgree,
		Domains:          TESTDOMAINS,
		PrivateKeyFile:   "testinguser.key",
		RegistrationFile: "testinguser.reg",
		Address:          TLSADDRESS,

		TLSCertFile: "cert.crt",
		TLSKeyFile:  "key.pem",

		RenewCallback: func() {
			domainchanged = true
		},
	})
	require.NoError(t, err)
	require.False(t, domainchanged)

	// Finally, we run one more time, but this time we change the domains - and check to see if renew is called
	// Now running again will not call domainchanged
	domainchanged = false
	_, err = New(Config{
		Server:           TESTAPI,
		TOSCallback:      TOSAgree,
		Domains:          newdomains,
		PrivateKeyFile:   "testinguser.key",
		RegistrationFile: "testinguser.reg",
		Address:          TLSADDRESS,

		TLSCertFile: "cert.crt",
		TLSKeyFile:  "key.pem",

		RenewCallback: func() {
			domainchanged = true
		},
	})
	require.NoError(t, err)
	require.True(t, domainchanged)
}
