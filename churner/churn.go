package churner

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/cmd"
	"github.com/go-acme/lego/v4/lego"

	"github.com/letsencrypt/crl-monitor/db"
)

type Churner struct {
	baseDomain string
	legoClient *lego.Client
	db         *db.Database
}

func New(baseDomain string) (*Churner, error) {
	// TODO: persistent acme client setup
	legoCfg := lego.NewConfig(&cmd.Account{})

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, err
	}

	awsCfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("error creating AWS config: %v", err)
	}

	return &Churner{
		baseDomain: baseDomain,
		legoClient: client,
		db:         db.New(awsCfg),
	}, nil
}

// Churn issues a certificate, revokes it, and stores the result in DynamoDB
func (c *Churner) Churn(ctx context.Context) error {
	resource, err := c.legoClient.Certificate.Obtain(certificate.ObtainRequest{
		Domains: []string{c.RandDomain()},
	})
	if err != nil {
		return err
	}

	var reason uint = 5
	err = c.legoClient.Certificate.RevokeWithReason(resource.Certificate, &reason)
	if err != nil {
		return err
	}

	certs, err := certcrypto.ParsePEMBundle(resource.Certificate)
	if err != nil {
		return err
	}

	return c.db.AddCert(ctx, certs[0], time.Now())
}

func (c *Churner) RandDomain() string {
	// TODO
	return "4byfairdiceroll." + c.baseDomain
}
