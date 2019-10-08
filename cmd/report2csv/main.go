package main

import (
	"encoding/csv"
	"encoding/json"
	"log"
	"os"
	"strconv"
)

type report struct {
	Time          string
	Mixes         int
	PeerCount     int
	ExcludedPeers int
	Mix           struct {
		TxHash       string
		Denomination int64
		TotalInput   int64
		Fee          int64
	}

	fields []string
}

func i64s(i int64) string {
	return strconv.FormatInt(i, 10)
}

func itoa(i int) string {
	return strconv.Itoa(i)
}

func (r *report) csvFields() []string {
	if r.fields == nil {
		r.fields = make([]string, 0, 8)
	}
	fields := r.fields
	fields = append(fields, r.Time, r.Mix.TxHash, itoa(r.Mixes),
		i64s(r.Mix.Denomination), i64s(r.Mix.TotalInput),
		i64s(r.Mix.Fee), itoa(r.PeerCount),
		itoa(r.ExcludedPeers))
	return fields
}

func main() {
	dec := json.NewDecoder(os.Stdin)
	w := csv.NewWriter(os.Stdout)
	defer w.Flush()
	var r report
	for dec.More() {
		err := dec.Decode(&r)
		if err != nil {
			log.Fatal(err)
		}
		w.Write(r.csvFields())
	}
}
