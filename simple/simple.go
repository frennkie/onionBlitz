package simple

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/cretz/bine/torutil/ed25519"
	"github.com/cretz/bine/torutil/geoipembed"
	"github.com/davecgh/go-spew/spew"
	"github.com/juju/errors"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"os/user"
	"time"

	"github.com/cretz/bine/tor"
)

func Init() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

// convertBase64StringToPrivateKey converts a Tor private key (which can be found in
// the file "hs_ed25519_secret_key") which was converted to base64 into a
// crypto.PrivateKey. Run `base64 -w0 hs_ed25519_secret_key` to extract key
// as base64 (the string will start with "PT0gZWQ...").
func convertBase64StringToPrivateKey(base64String string) (crypto.PrivateKey, error) {
	decodedFull, err := base64.StdEncoding.DecodeString(base64String)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("unable to decode base64 string: %s", err))
	}

	if len(decodedFull) != 96 {
		return nil, errors.New("invalid key: wrong length")
	}

	privateKey, err := hex.DecodeString(fmt.Sprintf("%x", decodedFull[32:]))
	if err != nil {
		return nil, errors.New(fmt.Sprintf("unable to hex decode string: %s", err))
	}

	return ed25519.PrivateKey(privateKey), nil
}

func convertSecretKeyFileToPrivateKey(filePath string) (crypto.PrivateKey, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("unable to open: %s: %v", filePath, err))
	}

	content := make([]byte, 96)
	n, err := f.Read(content)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("unable to read: %s: %v", filePath, err))
	}

	if n != 96 {
		return nil, errors.New(fmt.Sprintf("invalid file (wrong size - should be 96 bytes): %s:", filePath))
	}

	privateKey, err := hex.DecodeString(fmt.Sprintf("%x", content[32:]))
	if err != nil {
		return nil, errors.New(fmt.Sprintf("unable to hex decode string: %s", err))
	}

	return ed25519.PrivateKey(privateKey), nil
}

func run() error {

	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)

	log.SetFormatter(&log.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})

	cUser, err := user.Current()
	if err != nil {
		panic(err)
	}

	// Either
	//privateKey, err := convertBase64StringToPrivateKey("PT0gZWQyNTUxOXYxLXNlY3JldDogd" +
	//	"HlwZTAgPT0AAAAwWPL27NILiFMQuLjMj8qilAw4xuuRskVXfKGocY0cV7txgxEThtAK79N" +
	//	"5WNETbuzwJa3Gx7s5huY/Tx8+BdND")
	//if err != nil {
	//	log.WithFields(log.Fields{"err": err}).Fatal("failed to convert base64 string to PrivateKey")
	//}

	// Or
	privateKey, _ := convertSecretKeyFileToPrivateKey("example/" +
		"godemotpdkcjlyidqgn5l5rjupxjahq6ozv4o7du3dvqsktonhj4tjqd.onion/hs_ed25519_secret_key")

	// Start tor with default config (can set start mStartConf's DebugWriter to os.Stdout for debug logs)
	log.Info("Starting and registering onion service, please wait a couple of minutes...")
	mStartConf := tor.StartConf{
		ExePath:         cUser.HomeDir + "\\tor\\Tor\\tor.exe",
		DataDir:         cUser.HomeDir + "\\tor\\Data",
		TempDataDirBase: cUser.HomeDir + "\\tor\\Tor\\temp",
		GeoIPFileReader: geoipembed.GeoIPReader,
	}

	mListenConf := tor.ListenConf{
		LocalPort:   8080,
		RemotePorts: []int{80},
		Key:         privateKey,
		Version3:    true,
		//ClientAuths:            map[string]string{"" +
		//	"user": "",
		//},
	}

	t, err := tor.Start(nil, &mStartConf)
	if err != nil {
		return err
	}
	defer t.Close()
	// Add a handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		spew.Dump(r)
		log.WithFields(log.Fields{"url": r.URL}).Debug("received request")
		_, _ = w.Write([]byte("Hello, Dark World 2.0!"))
	})

	// Wait at most a few minutes to publish the service
	listenCtx, listenCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer listenCancel()
	// Create an onion service to listen on 8080 but show as 80
	//onion, err := t.Listen(listenCtx, &tor.ListenConf{LocalPort: 8080, RemotePorts: []int{80}})
	onion, err := t.Listen(listenCtx, &mListenConf)
	if err != nil {
		return err
	}
	defer onion.Close()
	// Serve on HTTP
	log.Infof("Open Tor browser and navigate to http://%v.onion", onion.ID)
	return http.Serve(onion, nil)
}
