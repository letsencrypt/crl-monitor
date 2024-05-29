module github.com/letsencrypt/crl-monitor

go 1.22.0

toolchain go1.22.2

require (
	github.com/aws/aws-lambda-go v1.47.0
	github.com/aws/aws-sdk-go-v2 v1.26.1
	github.com/aws/aws-sdk-go-v2/config v1.27.10
	github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue v1.13.13
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.31.1
	github.com/aws/aws-sdk-go-v2/service/s3 v1.53.1
	github.com/caddyserver/certmagic v0.20.0
	github.com/letsencrypt/boulder v0.0.0-20240424004736-7ee5b469a6a9
	github.com/libdns/route53 v1.3.3
	github.com/mholt/acmez v1.2.0
	github.com/stretchr/testify v1.9.0
	go.uber.org/zap v1.27.0
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.2 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.10 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/dynamodbstreams v1.20.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.3.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.9.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.17.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/route53 v1.40.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.20.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.23.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.28.6 // indirect
	github.com/aws/smithy-go v1.20.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-jose/go-jose/v4 v4.0.1 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.6 // indirect
	github.com/kr/pretty v0.3.0 // indirect
	github.com/libdns/libdns v0.2.2 // indirect
	github.com/miekg/dns v1.1.58 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/weppos/publicsuffix-go v0.30.3-0.20240411085455-21202160c2ed // indirect
	github.com/zeebo/blake3 v0.2.3 // indirect
	github.com/zmap/zcrypto v0.0.0-20231219022726-a1f61fb1661c // indirect
	github.com/zmap/zlint/v3 v3.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.22.0 // indirect
	golang.org/x/mod v0.14.0 // indirect
	golang.org/x/net v0.24.0 // indirect
	golang.org/x/sys v0.19.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/tools v0.17.0 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
