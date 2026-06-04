// Command scraper dumps the entire version history of CRLs
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type Issuer struct {
	Prefix      string
	Short       string
	Environment string
	Bucket      string
}

var (
	// It is possible to determine this information at runtime, by using the AIA cert to determine
	// the CRL prefix, which is sha1(Issuer's Subject)[..7]. But this list changes slowly, so it's
	// not really worth the code.
	issuers = map[string]Issuer{
		"http://r3.c.lencr.org/":      {Prefix: "20506757847264211", Short: "r3", Environment: "prod", Bucket: "le-crl-prod"},
		"http://e1.c.lencr.org/":      {Prefix: "67430855296768143", Short: "e1", Environment: "prod", Bucket: "le-crl-prod"},
		"http://e5.c.lencr.org/":      {Prefix: "8463769016270244", Short: "e5", Environment: "prod", Bucket: "le-crl-prod"},
		"http://e6.c.lencr.org/":      {Prefix: "59807078151219433", Short: "e6", Environment: "prod", Bucket: "le-crl-prod"},
		"http://e7.c.lencr.org/":      {Prefix: "60964145547838761", Short: "e7", Environment: "prod", Bucket: "le-crl-prod"},
		"http://e8.c.lencr.org/":      {Prefix: "39409295459939154", Short: "e8", Environment: "prod", Bucket: "le-crl-prod"},
		"http://e9.c.lencr.org/":      {Prefix: "31110014771015909", Short: "e9", Environment: "prod", Bucket: "le-crl-prod"},
		"http://r10.c.lencr.org/":     {Prefix: "29572344840711535", Short: "r10", Environment: "prod", Bucket: "le-crl-prod"},
		"http://r11.c.lencr.org/":     {Prefix: "7409306942694595", Short: "r11", Environment: "prod", Bucket: "le-crl-prod"},
		"http://r12.c.lencr.org/":     {Prefix: "58036202463912065", Short: "r12", Environment: "prod", Bucket: "le-crl-prod"},
		"http://r13.c.lencr.org/":     {Prefix: "32259589997855422", Short: "r13", Environment: "prod", Bucket: "le-crl-prod"},
		"http://r14.c.lencr.org/":     {Prefix: "26458629343095443", Short: "r14", Environment: "prod", Bucket: "le-crl-prod"},
		"http://ye1.c.lencr.org/":     {Prefix: "15121864070385704", Short: "ye1", Environment: "prod", Bucket: "le-crl-prod"},
		"http://ye2.c.lencr.org/":     {Prefix: "11216248321241435", Short: "ye2", Environment: "prod", Bucket: "le-crl-prod"},
		"http://ye3.c.lencr.org/":     {Prefix: "25784596091186334", Short: "ye3", Environment: "prod", Bucket: "le-crl-prod"},
		"http://yr1.c.lencr.org/":     {Prefix: "27437271743860294", Short: "yr1", Environment: "prod", Bucket: "le-crl-prod"},
		"http://yr2.c.lencr.org/":     {Prefix: "29076392620644760", Short: "yr2", Environment: "prod", Bucket: "le-crl-prod"},
		"http://yr3.c.lencr.org/":     {Prefix: "8671320929137997", Short: "yr3", Environment: "prod", Bucket: "le-crl-prod"},
		"http://stg-e1.c.lencr.org/":  {Prefix: "4169287449788112", Short: "stg-e1", Environment: "stg", Bucket: "le-crl-stg"},
		"http://stg-r3.c.lencr.org/":  {Prefix: "58367272336442518", Short: "stg-r3", Environment: "stg", Bucket: "le-crl-stg"},
		"http://stg-e5.c.lencr.org/":  {Prefix: "15225348384016519", Short: "stg-e5", Environment: "stg", Bucket: "le-crl-stg"},
		"http://stg-e6.c.lencr.org/":  {Prefix: "17820861098434744", Short: "stg-e6", Environment: "stg", Bucket: "le-crl-stg"},
		"http://stg-e7.c.lencr.org/":  {Prefix: "47232933130476073", Short: "stg-e7", Environment: "stg", Bucket: "le-crl-stg"},
		"http://stg-e8.c.lencr.org/":  {Prefix: "46976321144248399", Short: "stg-e8", Environment: "stg", Bucket: "le-crl-stg"},
		"http://stg-e9.c.lencr.org/":  {Prefix: "19871214657240562", Short: "stg-e9", Environment: "stg", Bucket: "le-crl-stg"},
		"http://stg-r10.c.lencr.org/": {Prefix: "68020589961194420", Short: "stg-r10", Environment: "stg", Bucket: "le-crl-stg"},
		"http://stg-r11.c.lencr.org/": {Prefix: "28857625597875079", Short: "stg-r11", Environment: "stg", Bucket: "le-crl-stg"},
		"http://stg-r12.c.lencr.org/": {Prefix: "35768502929761868", Short: "stg-r12", Environment: "stg", Bucket: "le-crl-stg"},
		"http://stg-r13.c.lencr.org/": {Prefix: "34377515378669764", Short: "stg-r13", Environment: "stg", Bucket: "le-crl-stg"},
		"http://stg-r14.c.lencr.org/": {Prefix: "50213926740952395", Short: "stg-r14", Environment: "stg", Bucket: "le-crl-stg"},
		"http://stg-ye1.c.lencr.org/": {Prefix: "51816688251801090", Short: "stg-ye1", Environment: "stg", Bucket: "le-crl-stg"},
		"http://stg-ye2.c.lencr.org/": {Prefix: "48471306034107219", Short: "stg-ye2", Environment: "stg", Bucket: "le-crl-stg"},
		"http://stg-ye3.c.lencr.org/": {Prefix: "38622039212951449", Short: "stg-ye3", Environment: "stg", Bucket: "le-crl-stg"},
		"http://stg-yr1.c.lencr.org/": {Prefix: "70136346555307663", Short: "stg-yr1", Environment: "stg", Bucket: "le-crl-stg"},
		"http://stg-yr2.c.lencr.org/": {Prefix: "27211217977121518", Short: "stg-yr2", Environment: "stg", Bucket: "le-crl-stg"},
		"http://stg-yr3.c.lencr.org/": {Prefix: "8473284859346140", Short: "stg-yr3", Environment: "stg", Bucket: "le-crl-stg"},
	}
)

const awsRegion = "us-west-2"

func main() {
	var (
		flagDateStart *time.Time
		flagDateEnd   *time.Time
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [-start DATETIME] [-end DATETIME] [-output DIR] [-jobs INT] CRL_URL\n", os.Args[0])
		fmt.Fprint(flag.CommandLine.Output(), `
Dumps the entire version history of a CRL from S3, given its URL provided in a
certificate's CRL Distribution Point. Provide the URL of an intermediate without
a shard (e.g. http://r13.c.lencr.org/) to fetch every shard's history at once.

You MUST be logged into the AWS CLI under an account with access to the CRL
buckets.

Examples:
  Fetch all versions of a CRL given its URL and output them to your current
  working directory.
    crl-history http://stg-e6.c.lencr.org/36.crl

  Fetch every shard belonging to an intermediate.
    crl-history http://r13.c.lencr.org/

  Fetch all versions and output them to a folder foo/
    crl-history -output foo/ http://stg-e6.c.lencr.org/36.crl

  Fetch all versions from between 1 day ago and 2 days ago.
    crl-history -start "2 days ago" -end "1 day ago" \
      http://stg-e6.c.lencr.org/36.crl

-start and -end shell out to GNU date for datetime parsing. See man date(1)
section DATE STRING for more details. Usually you can just type a date in any
format your heart pleases, and GNU date will figure it out.
`)
		fmt.Fprintln(flag.CommandLine.Output(), "Options:")
		flag.PrintDefaults()
	}
	flag.Func("start", "date range start", func(s string) error {
		d, err := gdate(s)
		if err != nil {
			return fmt.Errorf("gdate: %w", err)
		}
		flagDateStart = &d
		return nil
	})
	flag.Func("end", "date range end", func(s string) error {
		d, err := gdate(s)
		if err != nil {
			return fmt.Errorf("gdate: %w", err)
		}
		flagDateEnd = &d
		return nil
	})
	flagOutput := flag.String("output", "", "output folder (default current working directory)")
	flagConcurrency := flag.Int("jobs", 16, "number of parallel downloads (default 16)")
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}
	flagCRL := flag.Args()[0]

	if *flagConcurrency < 1 {
		log.Fatalf("-jobs must be at least 1")
	}

	dirName, err := os.Getwd()
	if err != nil {
		log.Fatalf("os.Getwd(): %s", err)
	}
	if flagOutput != nil && *flagOutput != "" {
		dirName = *flagOutput
	}
	dir, err := os.OpenRoot(dirName)
	if err != nil {
		log.Fatalf("os.OpenRoot(): %s", err)
	}

	start := time.Time{}
	if flagDateStart != nil {
		start = *flagDateStart
	}
	end := time.Now().AddDate(100, 0, 0)
	if flagDateEnd != nil {
		end = *flagDateEnd
	}
	if end.Before(start) {
		log.Fatalf("start must be before end")
	}

	crlRegex := regexp.MustCompile(`^(http:\/\/[-.\w]+)\/?([0-9]+\.crl)?\/?$`)
	crlMatches := crlRegex.FindStringSubmatch(flagCRL)
	if crlMatches == nil {
		log.Fatal("URL must be in format http://stg-e6.c.lencr.org or http://stg-e6.c.lencr.org/36.crl")
	}

	parsedIssuer := crlMatches[1] + "/"
	crl := crlMatches[2]
	issuer, ok := issuers[parsedIssuer]
	if !ok {
		log.Fatalf("unknown issuer for: %s", parsedIssuer)
	}

	// Listing by the full object key (prefix/36.crl) returns versions of just that shard;
	// listing by the issuer prefix alone (prefix/) returns versions of every shard.
	listPrefix := issuer.Prefix + "/" + crl

	target := crl
	if target == "" {
		target = "(all shards)"
	}
	slog.Info("fetching CRL versions", "issuer", issuer, "shard", target, "prefix", listPrefix)

	ctx := context.Background()

	sdkConfig, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion))
	if err != nil {
		log.Fatalf("unable to load AWS SDK config: %s", err)
	}
	client := s3.NewFromConfig(sdkConfig)

	if err := run(ctx, client, listPrefix, issuer, start, end, dir, *flagConcurrency); err != nil {
		log.Fatal(err)
	}
}

func run(
	ctx context.Context,
	client *s3.Client,
	listPrefix string,
	issuer Issuer,
	start time.Time,
	end time.Time,
	dir *os.Root,
	concurrency int,
) error {
	workers, errored, tx := runWorkers(ctx, concurrency, issuer, client, dir)

	// Only consider shard objects (prefix/<n>.crl), skipping any stray keys such as
	// "folder" placeholder objects that an issuer-wide prefix listing might return.
	shardKey := regexp.MustCompile(`/[0-9]+\.crl$`)

	params := &s3.ListObjectVersionsInput{
		Bucket: aws.String(issuer.Bucket),
		Prefix: aws.String(listPrefix),
	}
	paginator := s3.NewListObjectVersionsPaginator(client, params)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("failed to query S3: %w", err)
		}
		for _, version := range page.Versions {
			if !shardKey.MatchString(*version.Key) {
				continue
			}
			if !version.LastModified.Before(start) && !version.LastModified.After(end) {
				tx <- version
			}
		}
	}

	close(tx)
	workers.Wait()

	if errored.Load() {
		return errors.New("an error occurred while processing, see error logs")
	} else {
		return nil
	}
}

func runWorkers(ctx context.Context,
	concurrency int,
	issuer Issuer,
	client *s3.Client,
	dir *os.Root,
) (*sync.WaitGroup, *atomic.Bool, chan types.ObjectVersion) {
	var (
		wg      sync.WaitGroup
		errored atomic.Bool
		rx      = make(chan types.ObjectVersion)
	)
	for range concurrency {
		wg.Go(func() {
			for version := range rx {
				slog.Info(
					"processing version",
					"bucket", issuer.Bucket,
					"key", *version.Key,
					"version", *version.VersionId,
					"lastModified", version.LastModified,
				)

				err := func(version types.ObjectVersion) error {
					params := s3.GetObjectInput{
						Bucket:    &issuer.Bucket,
						Key:       version.Key,
						VersionId: version.VersionId,
					}

					object, err := client.GetObject(ctx, &params)
					if err != nil {
						return fmt.Errorf("failed to download from s3: %w", err)
					}
					defer object.Body.Close()

					shard := strings.TrimSuffix(path.Base(*version.Key), ".crl")
					fname := fmt.Sprintf(
						"%s-%s-%s-%s.crl",
						issuer.Short,
						shard,
						object.LastModified.UTC().Format("2006-01-02T15:04:05"),
						*version.VersionId,
					)
					f, err := dir.Create(fname)
					if err != nil {
						return fmt.Errorf("failed to create file: %w", err)
					}
					defer f.Close()

					if _, err := io.Copy(f, object.Body); err != nil {
						return fmt.Errorf("failed to write file: %w", err)
					}

					return nil
				}(version)

				if err != nil {
					slog.Error(
						"failed to process version",
						"bucket", issuer.Bucket,
						"key", *version.Key,
						"version", *version.VersionId,
						"error", err,
					)
					errored.Store(true)
				}
			}
		})
	}
	return &wg, &errored, rx
}

// Gdate returns the output of `date -d`. This is useful for getting time from a human readable
// string, without having to stress out about format. See `man(1) date`.
//
// This only works on MacOS or Linux, with GNU coreutils installed.
//
// This SHOULD NOT be exposed to untrusted input.
func gdate(date string) (time.Time, error) {
	gdate, err := gdateBinary()
	if err != nil {
		return time.Time{}, err
	}

	cmd, err := exec.Command(gdate, "-d", date, `+%s`).Output()
	if err != nil {
		return time.Time{}, err
	}

	t, err := strconv.ParseInt(strings.TrimSpace(string(cmd)), 10, 64)
	if err != nil {
		return time.Time{}, err
	}

	return time.Unix(t, 0), nil
}

func gdateBinary() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return "date", nil
	case "darwin":
		return "gdate", nil
	default:
		return "", fmt.Errorf("unknown platform: %s", runtime.GOOS)
	}
}
