package main

import (
	"io"
	"os"
	"testing"
)

func TestVersionFlag(t *testing.T) {
	oldArgs, oldStdout, oldVersion := os.Args, os.Stdout, version
	defer func() {
		os.Args, os.Stdout, version = oldArgs, oldStdout, oldVersion
	}()

	for _, want := range []string{"v1.2.3", "v1.2.3-abcdef0"} {
		t.Run(want, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			os.Stdout = w
			os.Args = []string{"dhcpv4-served", "--version"}
			version = want
			err = run()
			w.Close()
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r)
			if err != nil || string(got) != want+"\n" {
				t.Fatalf("version output = %q, error = %v; want %q", got, err, want+"\n")
			}
		})
	}
}
