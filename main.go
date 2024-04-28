package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-gandi/go-gandi/livedns"
	"k8s.io/client-go/kubernetes"
	"os"
	"strings"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	gcf "github.com/go-gandi/go-gandi/config"
	"github.com/rs/zerolog/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName,
		&gandiDNSProviderSolver{},
	)
}

type gandiDNSProviderSolver struct {
	kubernetesClient *kubernetes.Clientset
}

type gandiDNSProviderConfig struct {
	APIKeySecretRef              cmmeta.SecretKeySelector `json:"apiKeySecretRef"`
	PersonalAccessTokenSecretRef cmmeta.SecretKeySelector `json:"personalAccessTokenSecretRef"`
}

func (c *gandiDNSProviderSolver) Name() string {
	return "gandi"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *gandiDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	log.Info().Interface("data", cfg).Msg("Decoded configuration")

	config, err := c.prepareConfig(&cfg, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	gandiLiveDns := livedns.New(*config)

	domain, entry := c.getDomainAndEntry(ch)
	records, err := gandiLiveDns.GetDomainRecordsByName(domain, entry)
	if err != nil {
		return err
	}

	for _, record := range records {
		for _, value := range record.RrsetValues {
			if strings.Contains(value, ch.Key) {
				log.Info().Msg("TXT record found. It will be updated")

				_, err := gandiLiveDns.UpdateDomainRecordByNameAndType(domain, entry, "TXT", 300, []string{ch.Key})
				return err
			}
		}
	}

	// we should create record here
	_, err = gandiLiveDns.CreateDomainRecord(domain, entry, "TXT", 300, []string{ch.Key})
	return err
}

func (c *gandiDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	log.Info().
		Str("namespace", ch.ResourceNamespace).
		Str("fqdn", ch.ResolvedFQDN).
		Str("zone", ch.ResolvedZone).
		Msg("cleanup resource")

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	config, err := c.prepareConfig(&cfg, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	gandiLiveDns := livedns.New(*config)

	domain, entry := c.getDomainAndEntry(ch)
	records, err := gandiLiveDns.GetDomainRecordsByName(domain, entry)
	if err != nil {
		return fmt.Errorf("error fetching domain records for domain %s and entry %s", domain, entry)
	}

	for _, record := range records {
		for _, value := range record.RrsetValues {
			if strings.Contains(value, ch.Key) {
				err := gandiLiveDns.DeleteDomainRecord(domain, record.RrsetName, record.RrsetType)
				if err != nil {
					return fmt.Errorf("error deleting TXT record: %v", err)
				}
				return nil
			}
		}
	}

	return nil
}

func (c *gandiDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	log.Debug().Msg("Initialize function called")
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.kubernetesClient = cl

	return nil
}

func loadConfig(cfgJSON *extapi.JSON) (gandiDNSProviderConfig, error) {
	log.Debug().Msg("loadConfig function called")
	cfg := gandiDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (c *gandiDNSProviderSolver) prepareConfig(cfg *gandiDNSProviderConfig, namespace string) (*gcf.Config, error) {
	log.Debug().Msg("Fetching Key from k8s")

	if len(cfg.PersonalAccessTokenSecretRef.Name) > 0 {
		secret, err := c.getKeySecret(&cfg.PersonalAccessTokenSecretRef, namespace)
		if err != nil {
			return nil, err
		}

		return &gcf.Config{PersonalAccessToken: *secret}, nil
	}

	secret, err := c.getKeySecret(&cfg.APIKeySecretRef, namespace)
	if err != nil {
		return nil, err
	}

	return &gcf.Config{APIKey: *secret}, nil
}

func (c *gandiDNSProviderSolver) getKeySecret(secretRef *cmmeta.SecretKeySelector, namespace string) (*string, error) {
	log.Info().Str("secretName", secretRef.Name).Str("namespace", namespace).Msg("Try and fetch api key from k8s")

	secretObj, err := c.kubernetesClient.CoreV1().Secrets(namespace).Get(context.Background(), secretRef.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %v", err)
	}

	secretValue, isOk := secretObj.Data[secretRef.Key]
	if !isOk {
		return nil, fmt.Errorf("failed to get key %s from secret %s in namespace %s", secretRef.Key, secretRef.Name, namespace)
	}

	data := string(secretValue)
	data = strings.TrimSuffix(data, "\n")
	return &data, nil
}

func (c *gandiDNSProviderSolver) getDomainAndEntry(ch *v1alpha1.ChallengeRequest) (string, string) {
	entry := strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone)
	entry = strings.TrimSuffix(entry, ".")
	domain := strings.TrimSuffix(ch.ResolvedZone, ".")
	return domain, entry
}
