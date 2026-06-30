package main

// NOTE: This file is mostly AI generated and was cleaned up and
// reviewed by a human.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const minimalMain = `package main

import "fmt"

var version = "dev"

func main() { fmt.Println("hello", version) }
`

var (
	// The axis value lists. Order is fixed so combination generation is
	// deterministic. Index into these from a covering-array/Cartesian []int.
	trimpathVals  = []bool{true, false}
	vcsVals       = []vcsKind{vcsNone, vcsClean, vcsDirty, vcsNeedsCheckout}
	buildmodeVals = []string{"", "pie", "exe"} // "" == default
	tagsVals      = []bool{false, true}
	layoutVals    = []layoutKind{layoutRoot, layoutSubdir, layoutFiles, layoutInstall}
	ldflagsVals   = []ldKind{ldNone, ldStrip, ldX}

	// goEnv is the environment used for building fixtures and for running gorepro.
	// CGO is disabled because gorepro only supports CGO_ENABLED=0 (and the default
	// is CGO_ENABLED=1 wherever a C compiler is present). GOTOOLCHAIN=auto, combined
	// with a low "go" directive in each fixture's go.mod, guarantees that the
	// original build, gorepro's version probe, and gorepro's reproduction build all
	// resolve to the same toolchain with no version switch.
	goEnv = []string{"CGO_ENABLED=0", "GOTOOLCHAIN=auto"}
)

func TestReproMatrix(t *testing.T) {
	t.Parallel()

	for _, c := range combinations(testing.Short()) {
		t.Run(c.name(), func(t *testing.T) {
			t.Parallel()

			if reason, skip := c.skip(); skip {
				t.Skip(reason)
			}
			if !c.trimpath && !dockerAvailable() {
				t.Skip("docker not available (trimpath=off builds in Docker)")
			}
			bin, cwd := setupAndBuild(t, c)
			// Every generated combo is expected to reproduce given the args from
			// goreproArgs. A failure here is a finding: either a real gorepro
			// reproducibility bug, or a combo to document as a known exception.
			assertCode(t, successCode, "", cwd, c.goreproArgs(bin)...)
		})
	}
}

// TestReproKnownCases covers inputs gorepro cannot reproduce or cannot
// auto-detect, asserting the documented exit code and guidance instead of
// success. These are deliberately not part of the generated matrix.
func TestReproKnownCases(t *testing.T) {
	t.Parallel()

	t.Run("CGO", func(t *testing.T) {
		t.Parallel()

		src, out := newModule(t)
		bin := filepath.Join(out, "app")
		runCmd(t, src, []string{"CGO_ENABLED=1", "GOTOOLCHAIN=auto"},
			"go", "build", "-trimpath", "-buildvcs=false", "-o", bin, ".")
		assertCode(t, errCode, "was built with CGO enabled", src, bin)
	})

	t.Run("trimpath drops ldflags", func(t *testing.T) {
		t.Parallel()

		src, out := newModule(t)
		bin := filepath.Join(out, "app")
		goBuild(t, src, bin, []string{"-trimpath", "-buildvcs=false", "-ldflags=-s -w"})
		// -trimpath drops -ldflags from the metadata; without -b the stripped
		// binary can't be reproduced and gorepro should say why.
		assertCode(t, sizeDifferentCode,
			`"-trimpath" was set, if "-ldflags" was set`, src, bin)
	})

	t.Run("buildmode exe", func(t *testing.T) {
		t.Parallel()

		src, out := newModule(t)
		bin := filepath.Join(out, "app")
		goBuild(t, src, bin, []string{"-trimpath", "-buildvcs=false", "-buildmode=exe"})
		// gorepro can't tell -buildmode=exe from the default, so it builds with
		// -buildmode=default; the result differs only in the build ID. The exact
		// code is buildIDSameCode (4) when the build-ID difference is a single
		// contiguous region (e.g. go1.22) and hashesDifferentCode (3) when the
		// toolchain embeds the action ID more than once (e.g. go1.25, where
		// onlyBuildIDDifferent's single-occurrence scan misses the second copy).
		code, output := gorepro(t, src, bin)
		if code != buildIDSameCode && code != hashesDifferentCode {
			t.Fatalf("want exit %d or %d, got %d\n%s",
				buildIDSameCode, hashesDifferentCode, code, output)
		}
		if !strings.Contains(output, "-b=-buildmode=exe") {
			t.Fatalf("output should suggest -b=-buildmode=exe\n%s", output)
		}
	})
}

// buildGoreproBin compiles the gorepro binary once and returns its path. Tests
// exec this real binary instead of calling mainRetCode in-process so every case
// runs with fully isolated process state (the flag package, the package-level
// failReasons slice, the getGoModDir sync.OnceValues cache, color globals, ...).
var buildGoreproBin = sync.OnceValues(func() (string, error) {
	dir, err := os.MkdirTemp("", "gorepro-bin-*")
	if err != nil {
		return "", err
	}
	bin := filepath.Join(dir, "gorepro")
	// Build with the ambient toolchain (the repo's go.mod may require a newer Go
	// than is installed as "local", so do not force GOTOOLCHAIN here).
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("building gorepro: %w\n%s", err, out)
	}
	return bin, nil
})

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func runCmd(t *testing.T, dir string, env []string, name string, args ...string) {
	t.Helper()

	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

// newModuleBare creates a fresh module with only a go.mod and returns the source
// dir plus an out dir that lives *outside* the source tree, so writing the
// original binary (or its .repro) never dirties a git repo rooted at src.
func newModuleBare(t *testing.T) (src, out string) {
	t.Helper()

	base := t.TempDir()
	src = filepath.Join(base, "src")
	out = filepath.Join(base, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	// A deliberately low "go" directive so GOTOOLCHAIN=auto never triggers a
	// toolchain download/switch regardless of which Go runs the test.
	writeFile(t, filepath.Join(src, "go.mod"), "module demo\n\ngo 1.21\n")
	return src, out
}

// newModule is newModuleBare plus the minimal main package at the module root.
func newModule(t *testing.T) (src, out string) {
	t.Helper()

	src, out = newModuleBare(t)
	writeFile(t, filepath.Join(src, "main.go"), minimalMain)
	return src, out
}

func gitInit(t *testing.T, dir string) {
	t.Helper()

	runCmd(t, dir, nil, "git", "init", "-q")
	runCmd(t, dir, nil, "git", "config", "user.name", "test")
	runCmd(t, dir, nil, "git", "config", "user.email", "test@test.test")
	runCmd(t, dir, nil, "git", "config", "commit.gpgsign", "false")
	gitCommit(t, dir, "initial")
}

func gitCommit(t *testing.T, dir, msg string) {
	t.Helper()

	runCmd(t, dir, nil, "git", "add", "-A")
	runCmd(t, dir, nil, "git", "commit", "-q", "-m", msg)
}

// goBuild builds the fixture with `go build [flags] -o outPath [target...]`.
func goBuild(t *testing.T, dir, outPath string, flags []string, target ...string) {
	t.Helper()

	args := append([]string{"build"}, flags...)
	args = append(args, "-o", outPath)
	args = append(args, target...)
	runCmd(t, dir, goEnv, "go", args...)
}

// gorepro runs the compiled gorepro binary with cwd set to the source dir and
// returns its exit code and combined output.
func gorepro(t *testing.T, cwd string, args ...string) (int, string) {
	t.Helper()

	bin, err := buildGoreproBin()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), append(goEnv, "NO_COLOR=1")...)
	out, _ := cmd.CombinedOutput()
	return cmd.ProcessState.ExitCode(), string(out)
}

func assertCode(t *testing.T, wantCode int, wantSubstr, cwd string, args ...string) {
	t.Helper()

	code, out := gorepro(t, cwd, args...)
	if code != wantCode {
		t.Fatalf("want exit %d, got %d\n%s", wantCode, code, out)
	}
	if wantSubstr != "" && !strings.Contains(out, wantSubstr) {
		t.Fatalf("output missing %q\n%s", wantSubstr, out)
	}
}

// dockerAvailable reports whether a usable Docker daemon is reachable.
func dockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	return exec.Command("docker", "info").Run() == nil
}

type vcsKind int

const (
	vcsNone vcsKind = iota
	vcsClean
	vcsDirty
	vcsNeedsCheckout
)

func (v vcsKind) String() string {
	switch v {
	case vcsNone:
		return "none"
	case vcsClean:
		return "clean"
	case vcsDirty:
		return "dirty"
	case vcsNeedsCheckout:
		return "checkout"
	default:
		return "unknown"
	}
}

type layoutKind int

const (
	layoutRoot layoutKind = iota
	layoutSubdir
	layoutFiles
	layoutInstall
)

func (l layoutKind) String() string {
	switch l {
	case layoutRoot:
		return "root"
	case layoutSubdir:
		return "subdir"
	case layoutFiles:
		return "files"
	case layoutInstall:
		return "install"
	default:
		return "unknown"
	}
}

type ldKind int

const (
	ldNone ldKind = iota
	ldStrip
	ldX
)

func (l ldKind) String() string {
	switch l {
	case ldNone:
		return "none"
	case ldStrip:
		return "strip"
	case ldX:
		return "x"
	default:
		return "unknown"
	}
}

// flagString returns the -ldflags value for the kind, or "" for ldNone.
func (l ldKind) flagString() string {
	switch l {
	case ldStrip:
		return "-s -w"
	case ldX:
		return "-X main.version=v1.2.3"
	default:
		return ""
	}
}

func axisSizes() []int {
	return []int{
		len(trimpathVals), len(vcsVals), len(buildmodeVals),
		len(tagsVals), len(layoutVals), len(ldflagsVals),
	}
}

type combo struct {
	trimpath  bool
	vcs       vcsKind
	buildmode string
	tags      bool
	layout    layoutKind
	ldflags   ldKind
}

func comboFromIndices(idx []int) combo {
	return combo{
		trimpath:  trimpathVals[idx[0]],
		vcs:       vcsVals[idx[1]],
		buildmode: buildmodeVals[idx[2]],
		tags:      tagsVals[idx[3]],
		layout:    layoutVals[idx[4]],
		ldflags:   ldflagsVals[idx[5]],
	}
}

// name is a stable, -run-friendly identifier for the combo.
func (c combo) name() string {
	bm := c.buildmode
	if bm == "" {
		bm = "default"
	}
	return fmt.Sprintf("trimpath=%t/vcs=%s/bm=%s/tags=%t/layout=%s/ld=%s",
		c.trimpath, c.vcs, bm, c.tags, c.layout, c.ldflags)
}

// skip reports combos that are invalid to build (as opposed to combos that
// merely fail to reproduce, which would be a finding).
func (c combo) skip() (reason string, skip bool) {
	if c.tags && c.layout == layoutFiles {
		// `go build main.go` compiles only the listed file, so the build-tagged
		// extra.go is never part of the build and -tags has no effect.
		return "tags have no effect when only main.go is passed", true
	}
	if !c.trimpath && c.buildmode == "pie" {
		// trimpath=off builds the original with the host toolchain but gorepro
		// reproduces it in alpine Docker. PIE output is sensitive to the exact
		// toolchain *build* (the distro and alpine builds of the same Go version
		// produce different content IDs), so the bytes can't match in this
		// harness. This is a cross-environment artifact of the test, not a
		// gorepro defect: default/exe builds reproduce identically across the
		// two environments, only PIE doesn't.
		return "host-built vs alpine-rebuilt PIE bytes differ by toolchain build", true
	}
	return "", false
}

// goreproArgs returns the gorepro arguments needed to reproduce the combo,
// ending with the binary path. gorepro cannot auto-detect -buildmode=exe, and
// -trimpath strips -ldflags from the build metadata, so those are supplied here.
func (c combo) goreproArgs(bin string) []string {
	var args []string
	if c.buildmode == "exe" {
		args = append(args, "-b=-buildmode=exe")
	}
	if c.ldflags != ldNone && c.trimpath {
		args = append(args, "-b=-ldflags="+c.ldflags.flagString())
	}
	return append(args, bin)
}

// setupAndBuild creates the fixture for the combo, builds the original binary
// (into a dir outside any git repo), and returns the binary path and the cwd
// gorepro should run in.
func setupAndBuild(t *testing.T, c combo) (binPath, cwd string) {
	t.Helper()

	var src, out string
	var target []string // build/install target args
	mainDir := ""       // dir, relative to src, holding main.go (and extra.go)

	switch c.layout {
	case layoutSubdir:
		src, out = newModuleBare(t)
		mainDir = filepath.Join("cmd", "app")
		writeFile(t, filepath.Join(src, mainDir, "main.go"), minimalMain)
		target = []string{"./cmd/app"}
	case layoutFiles:
		src, out = newModule(t)
		target = []string{"main.go"}
	default: // layoutRoot, layoutInstall
		src, out = newModule(t)
		target = []string{"."}
	}

	if c.tags {
		writeFile(t, filepath.Join(src, mainDir, "extra.go"),
			"//go:build extra\n\npackage main\n\nfunc init() { _ = version }\n")
	}

	flags := []string{}
	if c.trimpath {
		flags = append(flags, "-trimpath")
	}
	if c.buildmode != "" {
		flags = append(flags, "-buildmode="+c.buildmode)
	}
	if c.tags {
		flags = append(flags, "-tags=extra")
	}
	if c.ldflags != ldNone {
		flags = append(flags, "-ldflags="+c.ldflags.flagString())
	}

	if c.vcs == vcsNone {
		flags = append(flags, "-buildvcs=false")
	} else {
		gitInit(t, src)
		flags = append(flags, "-buildvcs=true")
	}
	// dirty: an untracked file present at build time makes vcs.modified=true.
	if c.vcs == vcsDirty {
		writeFile(t, filepath.Join(src, "dirty.txt"), "x")
	}

	if c.layout == layoutInstall {
		binPath = filepath.Join(out, "demo")
		env := append(append([]string{}, goEnv...), "GOBIN="+out)
		args := append([]string{"install"}, flags...)
		args = append(args, target...)
		runCmd(t, src, env, "go", args...)
	} else {
		binPath = filepath.Join(out, "app")
		goBuild(t, src, binPath, flags, target...)
	}

	switch c.vcs {
	case vcsDirty:
		// Clean the tree so gorepro must re-dirty it (temp file) itself.
		if err := os.Remove(filepath.Join(src, "dirty.txt")); err != nil {
			t.Fatal(err)
		}
	case vcsNeedsCheckout:
		// Move HEAD past the recorded revision so gorepro must check it out.
		runCmd(t, src, nil, "git", "commit", "-q", "--allow-empty", "-m", "later")
	}

	return binPath, src
}

// combinations returns the combos to test: an all-pairs covering array in short
// mode, or the full Cartesian product otherwise.
func combinations(short bool) []combo {
	sizes := axisSizes()
	var idxs [][]int
	if short {
		idxs = pairwise(sizes)
	} else {
		idxs = cartesian(sizes)
	}
	combos := make([]combo, len(idxs))
	for i, idx := range idxs {
		combos[i] = comboFromIndices(idx)
	}
	return combos
}

// cartesian returns every []int with element i in [0, sizes[i]).
func cartesian(sizes []int) [][]int {
	total := 1
	for _, s := range sizes {
		total *= s
	}
	res := make([][]int, 0, total)
	idx := make([]int, len(sizes))
	for {
		res = append(res, append([]int(nil), idx...))
		i := len(sizes) - 1
		for ; i >= 0; i-- {
			idx[i]++
			if idx[i] < sizes[i] {
				break
			}
			idx[i] = 0
		}
		if i < 0 {
			break
		}
	}
	return res
}

// pair is an unordered pairing of two (axis, value) choices with axisA < axisB.
type pair struct{ aAxis, aVal, bAxis, bVal int }

func mkPair(a, av, b, bv int) pair {
	if a < b {
		return pair{a, av, b, bv}
	}
	return pair{b, bv, a, av}
}

// pairwise returns a deterministic all-pairs covering array over the given axis
// sizes: every value of every axis, and every pair of values across two axes,
// appears in at least one returned []int. It uses a greedy algorithm seeded by
// an uncovered pair each round, so every round makes progress.
func pairwise(sizes []int) [][]int {
	n := len(sizes)
	uncovered := map[pair]bool{}
	for a := range n {
		for b := a + 1; b < n; b++ {
			for av := range sizes[a] {
				for bv := range sizes[b] {
					uncovered[pair{a, av, b, bv}] = true
				}
			}
		}
	}

	gain := func(tc []int, a, av int) int {
		g := 0
		for b := range n {
			if b == a || tc[b] == -1 {
				continue
			}
			if uncovered[mkPair(a, av, b, tc[b])] {
				g++
			}
		}
		return g
	}

	var cases [][]int
	for len(uncovered) > 0 {
		// Deterministic seed: the lexicographically smallest uncovered pair.
		var seed pair
		first := true
		for p := range uncovered {
			if first || less(p, seed) {
				seed, first = p, false
			}
		}

		tc := make([]int, n)
		for i := range tc {
			tc[i] = -1
		}
		tc[seed.aAxis] = seed.aVal
		tc[seed.bAxis] = seed.bVal

		// Greedily fill the remaining axes, each time choosing the unassigned
		// (axis, value) that covers the most still-uncovered pairs.
		for {
			bestAxis, bestVal, bestGain := -1, -1, -1
			for a := range n {
				if tc[a] != -1 {
					continue
				}
				for av := range sizes[a] {
					if g := gain(tc, a, av); g > bestGain {
						bestAxis, bestVal, bestGain = a, av, g
					}
				}
			}
			if bestAxis == -1 {
				break
			}
			tc[bestAxis] = bestVal
		}

		for a := range n {
			for b := a + 1; b < n; b++ {
				delete(uncovered, pair{a, tc[a], b, tc[b]})
			}
		}
		cases = append(cases, tc)
	}
	return cases
}

func less(x, y pair) bool {
	if x.aAxis != y.aAxis {
		return x.aAxis < y.aAxis
	}
	if x.aVal != y.aVal {
		return x.aVal < y.aVal
	}
	if x.bAxis != y.bAxis {
		return x.bAxis < y.bAxis
	}
	return x.bVal < y.bVal
}
