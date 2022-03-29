package publish

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"go.mozilla.org/sops/v3"
	"go.mozilla.org/sops/v3/cmd/sops/common"
	"go.mozilla.org/sops/v3/config"
	"go.mozilla.org/sops/v3/keyservice"
	"go.mozilla.org/sops/v3/logging"
	"go.mozilla.org/sops/v3/publish"
)

var log *logrus.Logger

func init() {
	log = logging.NewLogger("PUBLISH")
}

// Opts represents publish options and config
type Opts struct {
	Interactive    bool
	Cipher         sops.Cipher
	ConfigPath     string
	InputPath      string
	KeyServices    []keyservice.KeyServiceClient
	InputStore     sops.Store
	OmitExtensions bool
	Recursive      bool
	RootPath       string
}

// Run publish operation
func Run(opts Opts) error {
	var fileContents []byte
	path, err := filepath.Abs(opts.InputPath)
	if err != nil {
		return err
	}

	conf, err := config.LoadDestinationRuleForFile(opts.ConfigPath, opts.InputPath, make(map[string]string))
	if err != nil {
		return err
	}
	if conf.Destination == nil {
		return errors.New("no destination configured for this file")
	}

	var destinationPath string
	if opts.Recursive {
		destinationPath, err = filepath.Rel(opts.RootPath, opts.InputPath)
		if err != nil {
			return err
		}
	} else {
		_, destinationPath = filepath.Split(path)
	}
	if opts.OmitExtensions || conf.OmitExtensions {
		destinationPath = strings.TrimSuffix(destinationPath, filepath.Ext(path))
	}

	// Check that this is a sops-encrypted file
	tree, err := common.LoadEncryptedFile(opts.InputStore, opts.InputPath)
	if err != nil {
		return err
	}

	data := map[string]interface{}{}

	switch conf.Destination.(type) {
	case *publish.VaultDestination:
		_, err = common.DecryptTree(common.DecryptTreeOpts{
			Cipher:      opts.Cipher,
			IgnoreMac:   false,
			Tree:        tree,
			KeyServices: opts.KeyServices,
		})
		if err != nil {
			return err
		}
		data, err = sops.EmitAsMap(tree.Branches)
		if err != nil {
			return err
		}
	}

	if opts.Interactive {
		var response string
		for response != "y" && response != "n" {
			fmt.Printf("uploading %s to %s ? (y/n): ", path, conf.Destination.Path(destinationPath))
			_, err := fmt.Scanln(&response)
			if err != nil {
				return err
			}
		}
		if response == "n" {
			msg := fmt.Sprintf("Publication of %s canceled", path)
			if opts.Recursive {
				fmt.Println(msg)
				return nil
			} else {
				return errors.New(msg)
			}
		}
	}

	switch dest := conf.Destination.(type) {
	case *publish.GCSDestination:
		err = dest.Upload(fileContents, destinationPath)
	case *publish.VaultDestination:
		err = dest.UploadUnencrypted(data, destinationPath)
	}

	if err != nil {
		return err
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
