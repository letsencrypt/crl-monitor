package mock

import (
	"context"
	"fmt"
	"math/big"
	"time"
)

type Fetcher struct {
	data map[string]time.Time
}

func (f *Fetcher) AddTestData(serial *big.Int, notAfter time.Time) {
	if f.data == nil {
		f.data = make(map[string]time.Time)
	}
	f.data[string(serial.Bytes())] = notAfter
}

func (f *Fetcher) FetchNotAfter(_ context.Context, serial *big.Int) (time.Time, error) {
	notAfter, ok := f.data[string(serial.Bytes())]
	if !ok {
		return time.Time{}, fmt.Errorf("unknown serial %d", serial)
	}
	return notAfter, nil
}
