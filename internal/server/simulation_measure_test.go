package server

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Set DST_MEASURE=1 to report the seed corpus and a reproducible random sample.
// Set DST_CORPUS_DIR to a Go fuzz corpus directory to include retained inputs.
func TestLeaseSequenceMeasurement(t *testing.T) {
	if os.Getenv("DST_MEASURE") != "1" {
		t.Skip("set DST_MEASURE=1 to collect sequence metrics")
	}
	const seed int64 = 1
	const samples = 10000
	report := func(name string, inputs [][]byte) {
		occurrences := map[string]int{}
		sequences := map[string]int{}
		signatures := map[string]bool{}
		for _, input := range inputs {
			seen := map[string]bool{}
			var events []string
			runLeaseSequence(t, input, func(event string) {
				occurrences[event]++
				seen[event] = true
				events = append(events, event)
			})
			for event := range seen {
				sequences[event]++
			}
			signatures[strings.Join(events, ",")] = true
		}
		names := []string{"lease_granted", "lease_renewed", "lease_expiry_attempt", "lease_expired", "quarantine_expiry_attempt", "quarantine_expired", "restart", "restart_after_deadline", "reassignment", "stale_selecting", "other_client_renewal", "renewal_after_reassignment", "grant_save_failure", "renewal_save_failure", "expiry_save_failure", "save_failed", "offer", "ack", "silence", "storage_error", "ack_delivered", "ack_lost", "replayed_selecting", "replayed_renewal", "replayed_stale_selecting", "replayed_renewal_after_reassignment", "released", "declined"}
		t.Logf("%s sequences=%d unique_event_traces=%d", name, len(inputs), len(signatures))
		for _, event := range names {
			t.Logf("%s %-28s sequences=%d occurrences=%d", name, event, sequences[event], occurrences[event])
		}
	}
	corpus := append([][]byte(nil), sequenceSeeds...)
	directories := []string{"testdata/fuzz/FuzzLeaseSequences"}
	if extra := os.Getenv("DST_CORPUS_DIR"); extra != "" {
		directories = append(directories, extra)
	}
	for _, dir := range directories {
		files, err := os.ReadDir(dir)
		if os.IsNotExist(err) && dir == directories[0] {
			continue
		}
		if err != nil {
			t.Fatalf("read corpus %s: %v", dir, err)
		}
		sort.Slice(files, func(i, j int) bool { return files[i].Name() < files[j].Name() })
		for _, file := range files {
			if file.IsDir() {
				continue
			}
			path := filepath.Join(dir, file.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) != 2 || lines[0] != "go test fuzz v1" || !strings.HasPrefix(lines[1], "[]byte(") || !strings.HasSuffix(lines[1], ")") {
				t.Fatalf("unsupported fuzz corpus entry %s", path)
			}
			value, err := strconv.Unquote(strings.TrimSuffix(strings.TrimPrefix(lines[1], "[]byte("), ")"))
			if err != nil {
				t.Fatalf("decode %s: %v", path, err)
			}
			corpus = append(corpus, []byte(value))
		}
	}
	report("corpus", corpus)
	rng := rand.New(rand.NewSource(seed))
	inputs := make([][]byte, samples)
	for i := range inputs {
		inputs[i] = make([]byte, rng.Intn(32)+1)
		for j := range inputs[i] {
			inputs[i][j] = byte(rng.Intn(256))
		}
	}
	report(fmt.Sprintf("sample(seed=%d)", seed), inputs)
	conditioned := make([][]byte, samples)
	for i := range conditioned {
		conditioned[i] = append([]byte{0, 1}, inputs[i]...)
	}
	report(fmt.Sprintf("acquired(seed=%d)", seed), conditioned)
}

func TestLeaseSequenceObservations(t *testing.T) {
	checks := []struct {
		seed  int
		event string
	}{{0, "reassignment"}, {0, "renewal_after_reassignment"}, {1, "expiry_save_failure"}, {4, "stale_selecting"}, {8, "released"}, {9, "declined"}, {10, "declined"}, {11, "quarantine_expired"}, {12, "save_failed"}}
	for _, check := range checks {
		seen := false
		runLeaseSequence(t, sequenceSeeds[check.seed], func(event string) {
			if event == check.event {
				seen = true
			}
		})
		if !seen {
			t.Errorf("seed %d did not reach %s", check.seed, check.event)
		}
	}
}

func TestQuarantineDoesNotCountAsRenewal(t *testing.T) {
	events := map[string]int{}
	runLeaseSequence(t, []byte{0, 1, 0x17, 8, 9, 0x2f, 2}, func(event string) { events[event]++ })
	if events["declined"] != 1 || events["reassignment"] != 1 {
		t.Fatalf("scenario did not reach reassigned quarantine: %v", events)
	}
	if events["other_client_renewal"] != 0 || events["renewal_after_reassignment"] != 0 {
		t.Fatalf("quarantine counted as live lease: %v", events)
	}
}
