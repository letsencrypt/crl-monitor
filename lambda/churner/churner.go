package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/letsencrypt/crl-monitor/churner"
)

func HandleRequest(ctx context.Context) error {
	c, err := churner.New("localhost")
	if err != nil {
		return fmt.Errorf("error in setup: %w", err)
	}

	err = c.Churn()
	if err != nil {
		return fmt.Errorf("error in churning: %w", err)
	}
	return nil
}

func main() {
	lambda.Start(HandleRequest)
}
