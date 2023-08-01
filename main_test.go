package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	os.Exit(testscript.RunMain(m, map[string]func() int{
		"gorepro": mainRetCode,
	}))
}

func TestScripts(t *testing.T) {
	params := testscript.Params{
		Dir: "testdata/scripts",
		Cmds: map[string]func(t *testscript.TestScript, neg bool, args []string){
			"sha256check": sha256check,
			"gunzip":      gunzip,
			"sha256cmp":   sha256cmp,
			"untar":       untar,
			"unzip":       unzip,
			"wget":        wget,
		},
		Setup: func(e *testscript.Env) error {
			// $HOME isn't set inside testscripts for some reason?
			e.Setenv("HOME", os.Getenv("HOME"))
			// tell gorepro not to use colors when printing so we can
			// match on stdout/stderr
			e.Setenv("NO_COLOR", "1")

			return nil
		},
		RequireExplicitExec: true,
		RequireUniqueNames:  true,
	}

	testscript.Run(t, params)
}

func gunzip(t *testscript.TestScript, neg bool, args []string) {
	if len(args) != 1 {
		t.Fatalf("usage: gunzip file")
	}
	if neg {
		t.Fatalf("gunzip: negation not supported")
	}

	cFile, err := os.Open(t.MkAbs(args[0]))
	if err != nil {
		t.Fatalf("error opening file: %v", err)
	}
	defer cFile.Close()

	r, err := gzip.NewReader(cFile)
	if err != nil {
		t.Fatalf("error reading compressed file: %v", err)
	}
	defer r.Close()

	outPath := args[0]
	if strings.HasSuffix(args[0], ".gz") {
		outPath = outPath[:len(outPath)-3]
	} else {
		outPath += ".uncmp"
	}
	uFile, err := os.Create(t.MkAbs(outPath))
	if err != nil {
		t.Fatalf("error creating file: %v", err)
	}
	defer uFile.Close()

	if _, err := io.Copy(uFile, r); err != nil {
		t.Fatalf("error uncompressing file: %v", err)
	}
}

func sha256check(t *testscript.TestScript, neg bool, args []string) {
	if len(args) != 2 {
		t.Fatalf("usage: sha256check file hash")
	}
	if neg {
		t.Fatalf("sha256check: negation not supported")
	}

	h := sha256.New()
	file, err := os.Open(t.MkAbs(args[0]))
	if err != nil {
		t.Fatalf("error opening file: %v", err)
	}
	defer file.Close()

	if _, err = io.Copy(h, file); err != nil {
		t.Fatalf("error hashing file: %v", err)
	}
	checkHash, err := hex.DecodeString(args[1])
	if err != nil {
		t.Fatalf("error decoding hash: %v", err)
	}

	if !bytes.Equal(h.Sum(nil), checkHash) {
		t.Fatalf("hashes not equal")
	}
}

func sha256cmp(t *testscript.TestScript, neg bool, args []string) {
	if len(args) != 2 {
		t.Fatalf("usage: sha256cmp file file")
	}
	if neg {
		t.Fatalf("sha256cmp: negation not supported")
	}

	h1 := sha256.New()
	h2 := sha256.New()
	file1, err := os.Open(t.MkAbs(args[0]))
	if err != nil {
		t.Fatalf("error opening file: %v", err)
	}
	defer file1.Close()
	file2, err := os.Open(t.MkAbs(args[0]))
	if err != nil {
		t.Fatalf("error opening file: %v", err)
	}
	defer file2.Close()

	if _, err = io.Copy(h1, file1); err != nil {
		t.Fatalf("error hashing file: %v", err)
	}
	if _, err = io.Copy(h2, file2); err != nil {
		t.Fatalf("error hashing file: %v", err)
	}
	if !bytes.Equal(h1.Sum(nil), h2.Sum(nil)) {
		t.Fatalf("hashes not equal")
	}
}

func untar(t *testscript.TestScript, neg bool, args []string) {
	if len(args) != 1 {
		t.Fatalf("usage: untar file")
	}
	if neg {
		t.Fatalf("untar: negation not supported")
	}

	cFile, err := os.Open(t.MkAbs(args[0]))
	if err != nil {
		t.Fatalf("error opening file: %v", err)
	}
	defer cFile.Close()

	r := tar.NewReader(cFile)

	for {
		hdr, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("error reading tar header: %v", err)
		}

		file, err := os.Create(t.MkAbs(hdr.Name))
		if err != nil {
			t.Fatalf("error creating file: %v", err)
		}
		defer file.Close()

		n, err := io.Copy(file, r)
		if err != nil {
			t.Fatalf("error unzipping file: %v", err)
		}
		if n != hdr.Size {
			t.Fatalf("tarred file truncated: %v", err)
		}

		if err := file.Chmod(0o777); err != nil {
			t.Fatalf("error changing permissions of file: %v", err)
		}
	}
}

func unzip(t *testscript.TestScript, neg bool, args []string) {
	if len(args) != 1 {
		t.Fatalf("usage: unzip file")
	}
	if neg {
		t.Fatalf("unzip: negation not supported")
	}

	r, err := zip.OpenReader(t.MkAbs(args[0]))
	if err != nil {
		t.Fatalf("error opening zip file: %v", err)
	}
	defer r.Close()

	for _, f := range r.File {
		zipFile, err := f.Open()
		if err != nil {
			t.Fatalf("error opening embedded file: %v", err)
		}
		defer zipFile.Close()
		file, err := os.Create(t.MkAbs(f.Name))
		if err != nil {
			t.Fatalf("error creating file: %v", err)
		}
		defer file.Close()

		n, err := io.Copy(file, zipFile)
		if err != nil {
			t.Fatalf("error unzipping file: %v", err)
		}
		if n != f.FileInfo().Size() {
			t.Fatalf("zipped file truncated: %v", err)
		}

		if err := file.Chmod(0o777); err != nil {
			t.Fatalf("error changing permissions of file: %v", err)
		}
	}
}

func wget(t *testscript.TestScript, neg bool, args []string) {
	if len(args) != 1 {
		t.Fatalf("usage: wget URL")
	}
	if neg {
		t.Fatalf("wget: negation not supported")
	}

	fileURL, err := url.Parse(args[0])
	if err != nil {
		t.Fatalf("error parsing URL: %v", err)
	}
	filePath := path.Base(fileURL.Path)

	file, err := os.Create(t.MkAbs(filePath))
	if err != nil {
		t.Fatalf("error creating file: %v", err)
	}
	defer file.Close()

	resp, err := http.Get(args[0])
	if err != nil {
		t.Fatalf("error making HTTP request: %v", err)
	}
	defer resp.Body.Close()

	n, err := io.Copy(file, resp.Body)
	if err != nil {
		t.Fatalf("error downloading file: %v", err)
	}
	if n != resp.ContentLength {
		t.Fatalf("downloaded file truncated")
	}
}
