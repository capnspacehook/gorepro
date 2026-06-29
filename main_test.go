package main

import (
	"testing"

	"github.com/blang/semver/v4"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		ver  string
		want semver.Version
	}{
		{
			ver: "1.18.0",
			want: semver.Version{
				Major: 1,
				Minor: 18,
				Patch: 0,
			},
		},
		{
			ver: "1.13",
			want: semver.Version{
				Major: 1,
				Minor: 13,
				Patch: 0,
			},
		},
		{
			ver: "1.27rc1",
			want: semver.Version{
				Major: 1,
				Minor: 27,
				Patch: 0,
				Pre: []semver.PRVersion{
					{
						VersionStr: "rc1",
					},
				},
			},
		},
		{
			ver: "1.13beta1",
			want: semver.Version{
				Major: 1,
				Minor: 13,
				Patch: 0,
				Pre: []semver.PRVersion{
					{
						VersionStr: "beta1",
					},
				},
			},
		},
		{
			ver: "2.67.5-tag4",
			want: semver.Version{
				Major: 2,
				Minor: 67,
				Patch: 5,
				Pre: []semver.PRVersion{
					{
						VersionStr: "tag4",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.ver, func(t *testing.T) {
			got, err := parseVersion(tt.ver)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got.String() != tt.want.String() {
				t.Errorf("want %s, got %s", tt.want, got)
			}
		})
	}
}

func TestTrimGoLogs(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: `go: downloading asdf
go version go1.15.2 linux/amd64
`,
			want: "go version go1.15.2 linux/amd64",
		},
		{
			input: "go version go1.15.2 linux/amd64\n",
			want:  "go version go1.15.2 linux/amd64",
		},
		{
			input: "go version go1.15.2 linux/amd64",
			want:  "go version go1.15.2 linux/amd64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			trimmed := trimGoLogs([]byte(tt.input))
			if string(trimmed) != tt.want {
				t.Errorf("want %q, got %q", tt.want, trimmed)
			}
		})
	}
}
