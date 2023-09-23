package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/fatih/color"
	"github.com/goretk/gore"
)

const (
	cmdLinePkg      = "command-line-arguments"
	goVersionPrefix = "go version go"

	dockerGoModCache   = "/go-mod-cache"
	dockerBuildDir     = "/build-dir"
	dockerGoBuildCache = "/go-build-cache"

	dockerfileTmpl = `
FROM golang:%s-alpine

RUN apk add --update-cache git \
	&& rm -rf /var/cache/apk/* \
	&& git config --global --add safe.directory '*'`

	reproSuffix = ".repro"
)

const (
	successCode int = iota
	errCode
	sizeDifferentCode
	hashesDifferentCode
	buildIDSameCode
)

var (
	infoColor    = color.New(color.FgBlue)
	warnColor    = color.New(color.FgYellow)
	errColor     = color.New(color.FgRed)
	almostColor  = color.New(color.FgMagenta)
	successColor = color.New(color.FgGreen)

	additionalFlags string
	dryRun          bool
	goDebug         bool
	noGoGC          bool
	verbose         bool

	goEnvVars = []string{
		"HOME",
		"PATH",
	}

	failReasons []failReason
)

func usage() {
	fmt.Fprintf(os.Stderr, `
Gorepro creates reproducible Go binaries.

	gorepro [flags] binary

It does this by creating a "go build" command from the embedded build
metadata in the specified Go binary that should produce an identical
binary. Gorepro will notify you if the specified binary was built in
such a way that makes reproducing it unlikely, or your build environment
is not suitable for reproducing.

If gorepro detects that a different version of Go was used to create
the specified binary than what is currently installed, gorepro will
build in a docker container with the correct Go version needed to
reproduce the specified binary. Note that gorepro requires that
binaries to reproduce be built
with go1.18 or later as earlier versions do not embed build metadata.

Gorepro requires that it be run in the directory where the source code
for the specified binary exists. Depending on how the specified binary
was built, Gorepro may require that it be run inside a cloned Git
repository that the specified binary was built from. The binary to
reproduce is not required to be in any specific directory however.

For example, to reproduce a Go binary:

	gorepro ./gobin

To specify required build arguments that are not detected:

	gorepro -b=-buildmode=pie ./gobin

gorepro accepts the following flags:

`[1:])
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `

For more information, see https://github.com/capnspacehook/gorepro.
`[1:])
}

type failReason struct {
	reason          string
	ifSizeDifferent bool
}

func addFailReason(ifSizeDifferent bool, format string, a ...any) {
	failReasons = append(failReasons,
		failReason{
			reason:          fmt.Sprintf(format, a...),
			ifSizeDifferent: ifSizeDifferent,
		},
	)
}

func verbosef(format string, a ...any) {
	if !verbose {
		return
	}
	infof(format, a...)
}

func infof(format string, a ...any) {
	if dryRun {
		return
	}
	infoColor.Printf(format, a...)
	infoColor.Printf("\n")
}

func warnf(format string, a ...any) {
	warnColor.Printf(format, a...)
	warnColor.Printf("\n")
}

func errf(format string, a ...any) {
	errColor.Printf(format, a...)
	errColor.Printf("\n")
}

func almostf(format string, a ...any) {
	almostColor.Printf(format, a...)
	almostColor.Printf("\n")
}

func successf(format string, a ...any) {
	successColor.Printf(format, a...)
	successColor.Printf("\n")
}

func parseVersion(version string) (semver.Version, error) {
	if i := strings.Index(version, "beta"); i != -1 {
		version = version[i-1:] + "-" + version[:i]
	} else if i := strings.Index(version, "rc"); i != -1 {
		version = version[i-1:] + "-" + version[:i]
	} else if strings.Count(version, ".") == 1 {
		version += ".0"
	}
	ver, err := semver.Parse(version)
	if err != nil {
		return semver.Version{}, err
	}

	return ver, err
}

func getBuildID(ctx context.Context, file string) ([]byte, error) {
	return runCommand(ctx, "go", "tool", "buildid", file)
}

func runCommand(ctx context.Context, name string, arg ...string) ([]byte, error) {
	var buf bytes.Buffer
	var w io.Writer = &buf
	if verbose {
		w = io.MultiWriter(w, os.Stderr)
	}

	cmd := exec.CommandContext(ctx, name, arg...)
	verbosef("running command: %s", cmd)
	cmd.Stdout = w
	cmd.Stderr = w
	err := cmd.Run()
	if err != nil {
		return buf.Bytes(), err
	}

	return buf.Bytes(), nil
}

func main() {
	os.Exit(mainRetCode())
}

type errJustExit int

func (e errJustExit) Error() string { return fmt.Sprintf("exit: %d", e) }

type errWithRetCode struct {
	error

	code int
}

func errWithCode(code int, err error) error {
	return errWithRetCode{
		error: err,
		code:  code,
	}
}

func mainRetCode() int {
	err := mainErr()
	if err == nil {
		return successCode
	}

	var errRetCode *errJustExit
	var errAndRetCode *errWithRetCode
	var retCode int
	if errors.As(err, &errRetCode) {
		retCode = int(*errRetCode)
	} else if errors.As(err, &errAndRetCode) {
		retCode = errAndRetCode.code
		errf("error %v", errAndRetCode)
	} else {
		errf("error %v", err)
		retCode = errCode
	}

	if retCode > successCode && len(failReasons) != 0 {
		var sb strings.Builder
		var reasonsListed int
		sb.WriteString(warnColor.Sprint("reasons reproducing may have failed:\n"))
		for _, reason := range failReasons {
			// skip warnings that only apply if the produced binary has
			// a different size than the specified binary and it has
			// the same size
			if retCode != sizeDifferentCode && reason.ifSizeDifferent {
				continue
			}
			sb.WriteString(warnColor.Sprintf(" - %s\n", reason.reason))
			reasonsListed++
		}
		if reasonsListed != 0 {
			fmt.Print(sb.String())
		}
	}

	return retCode
}

func mainErr() error {
	flag.Usage = usage
	flag.StringVar(&additionalFlags, "b", "", "extra build flags that are needed to reproduce but aren't detected, comma separated")
	flag.BoolVar(&dryRun, "d", false, "print build commands instead of running them")
	flag.BoolVar(&goDebug, "godebug", false, "print very verbose debug information from the Go compiler")
	flag.BoolVar(&noGoGC, "no-go-gc", false, "trade memory usage for speed by disabling the garbage collector when compiling")
	flag.BoolVar(&verbose, "v", false, "print commands being run and verbose information")
	flag.Parse()

	if dryRun && verbose {
		return fmt.Errorf("-d and -v are mutually exclusive")
	}

	var extraFlags []string
	if len(additionalFlags) != 0 {
		extraFlags = strings.Split(additionalFlags, ",")
	}

	// ensure the go command is present
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf(`finding "go": %w`, err)
	}

	if flag.NArg() == 0 {
		usage()
		return errJustExit(errCode)
	} else if flag.NArg() > 1 {
		fmt.Fprintf(os.Stderr, "only one binary can be reproduced at a time\n\nusage:\n\n")
		usage()
		return errJustExit(errCode)
	}
	binary := flag.Arg(0)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// read the binary's build info
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		return fmt.Errorf("parsing build metadata: %w", err)
	}
	binVersionStr := info.GoVersion
	if len(binVersionStr) > 2 {
		binVersionStr = binVersionStr[2:]
	}
	binVer, err := parseVersion(binVersionStr)
	if err != nil {
		return fmt.Errorf("parsing go version of %q: %w", binary, err)
	}
	// check if binary can be reproduced
	if binVer.Minor < 18 {
		return fmt.Errorf("%q was built with go%s, only go1.18 or newer embeds build metadata that is required by gorepro",
			binary,
			binVersionStr,
		)
	}
	if len(info.Settings) == 0 {
		return fmt.Errorf("no build metadata present in %q, reproducing is possible but not supported by gorepro", binary)
	}

	if binVer.Minor < 20 {
		addFailReason(
			true,
			`%q was built with go%s which doesn't include what "-buildmode" was set to, a non default build mode may have been used`,
			binary,
			binVersionStr,
		)
	}

	file, err := gore.Open(binary)
	if err != nil {
		return err
	}
	defer file.Close()

	// check if source files for the main module need to be explicitly
	// passed
	var mainSrcFiles []string
	if info.Path == cmdLinePkg {
		p, err := file.GetPackages()
		if err != nil {
			return err
		}
		for _, pkg := range p {
			if pkg.Name == "main" {
				srcFiles := file.GetSourceFiles(pkg)
				for _, srcFile := range srcFiles {
					mainSrcFiles = append(mainSrcFiles, srcFile.Name)
				}
				break
			}
		}
	} else if info.Main.Version != "" && info.Main.Version != "(devel)" {
		return fmt.Errorf(`%q was built using "go install", reproducing is possible but not supported by gorepro`, binary)
	}

	// ensure main module source files exist
	if len(mainSrcFiles) != 0 {
		for _, file := range mainSrcFiles {
			if _, err := os.Stat(file); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf(`%q was built by passing %q to "go build", but that file couldn't be found; rerun gorepro in the directory with %q`,
						binary,
						file,
						file,
					)
				}
				return fmt.Errorf("reading build file: %w", err)
			}
		}
	}

	// get the version of the go command, we may have to download
	// a different version if it's not available
	out, err := runCommand(ctx, "go", "version")
	if err != nil {
		return fmt.Errorf(`running "go version": %w`, err)
	}

	if len(out) < len(goVersionPrefix) {
		return fmt.Errorf(`malformed "go version" output`)
	}
	out = out[len(goVersionPrefix):]
	i := bytes.IndexByte(out, ' ')
	if i == -1 {
		return fmt.Errorf(`malformed "go version" output`)
	}
	goVersionStr := string(out[:i])

	// build command that will hopefully reproduce the binary from its
	// embedded build information
	var buildArgs []string
	var env []string
	var buildIDExplicitlySet bool
	var trimpathFound bool
	var vcsUsed string
	var vcsRev string
	var vcsModified bool
	for _, setting := range info.Settings {
		switch setting.Key {
		case "-asmflags", "-buildmode", "-gcflags", "-ldflags", "-tags":
			if setting.Key == "ldflags" {
				if strings.Contains(setting.Value, "-buildid") {
					buildIDExplicitlySet = true
				}
			}

			if dryRun {
				buildArgs = append(buildArgs, fmt.Sprintf(`%s=%q`, setting.Key, setting.Value))
			} else {
				buildArgs = append(buildArgs, fmt.Sprintf("%s=%s", setting.Key, setting.Value))
			}
		case "-compiler":
			if setting.Value != "gc" {
				//lint:ignore ST1005 'Go' should be capitalized consistently
				return fmt.Errorf("Go compiler %s was used to build %s, only the building with the official Go compiler gc is supported",
					setting.Value,
					binary,
				)
			}
		case "-trimpath":
			trimpathFound = true
			if binVer.Minor <= 21 {
				addFailReason(
					false,
					`Go <= 1.21 was used to build %q and "-trimpath" was set, if "-ldflags" was set at build time it won't be in embedded build data`,
					binary,
				)
			}

			buildArgs = append(buildArgs, setting.Key)
		case "vcs":
			vcsUsed = setting.Value
		case "vcs.modified":
			if setting.Value == "true" {
				vcsModified = true
				addFailReason(
					false,
					"the Git repo %q was built in had uncommitted file(s) when it was built, you may be trying to build with different source code",
					binary,
				)
			}
		case "vcs.revision":
			vcsRev = setting.Value
			buildArgs = append(buildArgs, "-buildvcs=true")
		case "CGO_ENABLED":
			if setting.Value != "0" {
				return fmt.Errorf("%q was built with CGO enabled, reproducing is possible but not supported by gorepro", binary)
			}
			env = append(env, "CGO_ENABLED=0")
		case "GOAMD64", "GOARCH", "GOARM", "GOEXPERIMENT", "GOMIPS", "GOMIPS64", "GOOS", "GOPPC64", "GOWASM":
			env = append(env, fmt.Sprintf("%s=%s", setting.Key, setting.Value))
		}
	}

	// try and determine if -trimpath was set and gather necessary information
	// needed to reproduce if it wasn't
	var dockerInfo *dockerBuildInfo
	if !trimpathFound {
		setTrimpath, di, err := checkTrimpath(binVer, file, binary)
		if err != nil {
			return err
		}
		if setTrimpath {
			buildArgs = append(buildArgs, "-trimpath")
		}
		dockerInfo = di
	}

	// if the binary was built with VCS info embedded, check that our
	// build env is compatible and if not make it so
	if vcsUsed != "" {
		tempFile, checkedOut, err := checkVCS(ctx, vcsUsed, vcsRev, vcsModified, binary)
		if err != nil {
			return err
		}
		if tempFile != "" {
			defer func() {
				if err := os.Remove(tempFile); err != nil {
					warnf("error removing temporary file: %v", err)
				}
			}()
		}
		if checkedOut {
			if dryRun {
				defer fmt.Println("git checkout -q -")
			} else {
				defer func() {
					_, _ = runCommand(ctx, "git", "checkout", "-q", "-")
				}()
			}
		}
	} else {
		buildArgs = append(buildArgs, "-buildvcs=false")
	}

	// try to reproduce the binary
	if len(extraFlags) != 0 {
		buildArgs = append(buildArgs, extraFlags...)
	}
	ourBinary := binary + reproSuffix
	if binVersionStr != goVersionStr && dockerInfo == nil {
		dockerInfo = &dockerBuildInfo{
			goModCache: dockerGoModCache,
			buildDir:   dockerBuildDir,
		}
	}
	if dockerInfo != nil {
		if err := fillDockerCodeDirs(ctx, dockerInfo); err != nil {
			return err
		}
	}
	err = attemptRepro(ctx, binary, ourBinary, vcsUsed != "", binVer, env, buildArgs, mainSrcFiles, dockerInfo)
	if err != nil {
		return err
	}
	if dryRun {
		return nil
	}

	// check that file sizes match
	binfi, err := os.Stat(binary)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}
	ourBinfi, err := os.Stat(ourBinary)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	if binfi.Size() != ourBinfi.Size() {
		return errWithCode(sizeDifferentCode, fmt.Errorf("failed to reproduce: file sizes don't match"))
	}

	// check that file hashes match
	binf, err := os.Open(binary)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer binf.Close()
	ourBinf, err := os.Open(ourBinary)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer ourBinf.Close()

	binHash := sha256.New()
	if _, err := io.Copy(binHash, binf); err != nil {
		return fmt.Errorf("hashing %q: %w", binary, err)
	}
	ourBinHash := sha256.New()
	if _, err := io.Copy(ourBinHash, ourBinf); err != nil {
		return fmt.Errorf("hashing %q: %w", ourBinary, err)
	}
	binSum, ourBinSum := binHash.Sum(nil), ourBinHash.Sum(nil)
	infof("%x  %q", binSum, binary)
	infof("%x  %q", ourBinSum, ourBinary)

	if !bytes.Equal(binSum, ourBinSum) {
		errf("failed to reproduce: file hashes don't match")
		// if the build ID was explicitly set via a linker flag, don't
		// check the differences between build IDs, they will be the same
		if buildIDExplicitlySet {
			return errJustExit(hashesDifferentCode)
		}

		binBuildID, err := getBuildID(ctx, binary)
		if err != nil {
			return errWithCode(hashesDifferentCode, fmt.Errorf("getting build ID of %q: %w", binary, err))
		}
		if _, err := binf.Seek(0, io.SeekStart); err != nil {
			return errWithCode(hashesDifferentCode, fmt.Errorf("seeking to beginning of %q: %w", binary, err))
		}
		ourBinBuildID, err := getBuildID(ctx, ourBinary)
		if err != nil {
			return errWithCode(hashesDifferentCode, fmt.Errorf("getting build ID of %q: %w", ourBinary, err))
		}
		if _, err := ourBinf.Seek(0, io.SeekStart); err != nil {
			return errWithCode(hashesDifferentCode, fmt.Errorf("seeking to beginning of %q: %w", ourBinary, err))
		}

		// if the build IDs are different but the rest of the binaries'
		// contents match tell the user
		restSame, err := onlyBuildIDDifferent(binf, ourBinf, binBuildID, ourBinBuildID)
		if err != nil {
			return errWithCode(hashesDifferentCode, fmt.Errorf("comparing binaries: %w", err))
		}

		if restSame {
			almostf("however, only the build ID differs between binaries, binaries are almost the same")
			return errJustExit(buildIDSameCode)
		} else {
			binBuildIDParts := bytes.Split(binBuildID, []byte("/"))
			ourBinBuildIDParts := bytes.Split(ourBinBuildID, []byte("/"))

			if bytes.Equal(binBuildIDParts[2], ourBinBuildIDParts[2]) {
				almostf("the main module's compiled code is the same between binaries")
			}
		}

		return errJustExit(hashesDifferentCode)
	}

	successf("reproduced successfully! new binary is at %q", ourBinary)

	return nil
}

type dockerBuildInfo struct {
	goModCache       string
	buildDir         string
	localCodeDir     string
	containerCodeDir string
}

func checkTrimpath(binVer semver.Version, file *gore.GoFile, binary string) (bool, *dockerBuildInfo, error) {
	// Go 1.19+ adds -trimpath to the build metadata, on earlier Go
	// versions we can't always know for sure if it was passed
	trimpathUnknown := true
	if binVer.Minor >= 19 {
		trimpathUnknown = false
	}

	// detect if -trimpath was passed by inspecting the binary's GOROOT
	goRoot, err := file.GetGoRoot()
	if err != nil {
		if errors.Is(err, gore.ErrNoGoRootFound) {
			// if we don't know if -trimpath was set
			if trimpathUnknown {
				addFailReason(
					false,
					`"-trimpath" may not have been set when building %q, it could not be detected from embedded build metadata`,
					binary,
				)
				return true, nil, nil
			}
		} else {
			return false, nil, fmt.Errorf("finding GOROOT of %q: %w", binary, err)
		}
	}
	// GOROOT will be 'go' if -trimpath was set
	if goRoot == "go" {
		return true, nil, nil
	}
	if goRoot != "" {
		trimpathUnknown = false
	}

	// find GOMODCACHE
	findGoModCache := func(pkgs []*gore.Package) string {
		for _, pkg := range pkgs {
			name := pkg.Name
			// get first part of package name
			if strings.Contains(name, "/") {
				s, _, ok := strings.Cut(pkg.Name, "/")
				if !ok {
					continue
				}
				name = s
			}

			// get dir before package name
			path, _, ok := strings.Cut(pkg.Filepath, name)
			if !ok {
				continue
			}
			// package is stdlib, continue
			if strings.HasPrefix(path, goRoot) {
				continue
			}

			return path
		}

		return ""
	}

	thirdPartyPkgs, err := file.GetVendors()
	if err != nil {
		return false, nil, fmt.Errorf("getting packages of %q: %w", binary, err)
	}
	goModCache := findGoModCache(thirdPartyPkgs)
	if goModCache == "" {
		unknownPkgs, err := file.GetUnknown()
		if err != nil {
			return false, nil, fmt.Errorf("getting packages of %q: %w", binary, err)
		}
		goModCache = findGoModCache(unknownPkgs)
	}

	// get the build dir the binary was built in
	mainPkgs, err := file.GetPackages()
	if err != nil {
		return false, nil, fmt.Errorf("getting packages of %q: %w", binary, err)
	}
	var buildDir string
	for _, pkg := range mainPkgs {
		if pkg.Name == "main" {
			buildDir = pkg.Filepath
			break
		}
	}

	cwd, err := os.Getwd()
	if err != nil {
		return false, nil, err
	}
	if cwd != buildDir && trimpathUnknown {
		addFailReason(
			false,
			`"-trimpath" may not have been set when building %q, and %q was used as the build directory while you are using %q`,
			binary,
			buildDir,
			cwd,
		)
	}

	return false, &dockerBuildInfo{
		goModCache: goModCache,
		buildDir:   buildDir,
	}, nil
}

func trimNewline(b []byte) []byte {
	if len(b) != 0 && b[len(b)-1] == '\n' {
		return b[:len(b)-1]
	}
	return b
}

func min(i, j int) int {
	if i < j {
		return i
	}
	return j
}

func checkVCS(ctx context.Context, vcsUsed, vcsRev string, vcsModified bool, binary string) (string, bool, error) {
	var ok bool
	var tempFileName string
	// if we didn't return successfully and a temp file was created, delete
	// it so the caller doesn't have to worry about it
	defer func() {
		if tempFileName != "" && !ok {
			defer func() {
				if err := os.Remove(tempFileName); err != nil {
					warnf("error removing temporary file: %v", err)
				}
			}()
		}
	}()

	if vcsUsed != "git" {
		addFailReason(false, "version control system %s isn't supported by gorepro", vcsUsed)
		return "", false, nil
	}

	if _, err := exec.LookPath("git"); err != nil {
		return "", false, fmt.Errorf(`could not find "git": %w`, err)
	}
	gitStatus, err := runCommand(ctx, "git", "status", "--porcelain=v1")
	if err != nil {
		if strings.HasPrefix(string(gitStatus), "fatal: not a git repository") {
			return "", false, fmt.Errorf("%q was built in a Git repo, but gorepro wasn't run in one; reproducing will fail", binary)
		}
		return "", false, fmt.Errorf("getting Git status: %s %w", gitStatus, err)
	}

	// if there are new/modified Go source files present, chances are
	// the source code won't match what the original binary was compiled
	// with
	if len(gitStatus) != 0 {
		scanner := bufio.NewScanner(bytes.NewReader(gitStatus))
		for scanner.Scan() {
			// separate status symbol from file path
			// lines look like this:
			//  M main.go
			// ?? new.go
			txt := scanner.Text()
			if len(txt) < 4 {
				return "", false, fmt.Errorf(`error parsing "git status --porcelain: line too short: %s`, txt)
			}
			_, file, ok := strings.Cut(txt[1:], " ")
			if !ok {
				return "", false, fmt.Errorf(`error parsing "git status --porcelain: line malformed: %s`, txt)
			}

			_, file = filepath.Split(file)
			if strings.HasSuffix(file, ".go") || file == "go.mod" || file == "go.sum" {
				addFailReason(
					false,
					"there is at least one new or modified Go file in the local Git repo, source code may differ from what %q was built with",
					binary,
				)
				break
			}
		}
		if err := scanner.Err(); err != nil {
			return "", false, fmt.Errorf(`error parsing "git status" output: %w`, err)
		}
	}

	if !dryRun && vcsModified && len(gitStatus) == 0 {
		infof("%q was built in a dirty Git repo but the local Git repo is clean; creating a temporary file to make local Git repo dirty",
			binary,
		)
		tempFile, err := os.CreateTemp(".", "*")
		if err != nil {
			return "", false, fmt.Errorf("creating temporary file: %w", err)
		}
		tempFileName = tempFile.Name()
		tempFile.Close()
	} else if !vcsModified && len(gitStatus) != 0 {
		return "", false, fmt.Errorf("%q was built in a clean Git repo, and the local Git repo isn't clean; reproducing will fail", binary)
	}

	gitShow, err := runCommand(ctx, "git", "-c", "log.showsignature=false", "show", "-s", "--format=%H")
	if err != nil {
		return "", false, fmt.Errorf("getting latest git commit: %s %w", gitShow, err)
	}
	latestCommit := string(trimNewline(gitShow))
	var checkedOut bool
	if vcsRev != latestCommit {
		checkedOut = true
		if dryRun {
			fmt.Printf("git checkout -q %s\n", vcsRev)
		} else {
			infof("%q was built on commit %s but we're on %s, checking out correct commit", binary, vcsRev, latestCommit)
			out, err := runCommand(ctx, "git", "checkout", "-q", vcsRev)
			if err != nil {
				return "", false, fmt.Errorf("checking out git commit: %s %w", out, err)
			}
		}
	}

	ok = true

	return tempFileName, checkedOut, nil
}

func fillDockerCodeDirs(ctx context.Context, dockerInfo *dockerBuildInfo) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	dockerInfo.localCodeDir = cwd

	// figure out where module starts (where go.mod is) and mount accordingly
	goMod, err := runCommand(ctx, "go", "env", "GOMOD")
	if err != nil {
		return fmt.Errorf(`error running "go env": %s %w`, goMod, err)
	}
	goMod = trimNewline(goMod)
	const goModFilenameLen = len("/go.mod")
	if goModStr := string(goMod); len(goModStr) > goModFilenameLen && goModStr != os.DevNull {
		dockerInfo.localCodeDir = goModStr[:len(goModStr)-goModFilenameLen]
	}

	dockerInfo.containerCodeDir = dockerInfo.buildDir
	if dockerInfo.localCodeDir != cwd {
		sep := string(filepath.Separator)
		buildDirParts := strings.Split(dockerInfo.buildDir, sep)
		cwdParts := strings.Split(cwd, sep)
		for i := 1; i < min(len(buildDirParts), len(cwdParts)); i++ {
			if buildDirParts[len(buildDirParts)-i] != cwdParts[len(cwdParts)-i] {
				// TODO: if buildDir doesn't change, probably should report error to user
				// they probably aren't in correct dir
				dockerInfo.containerCodeDir = sep + filepath.Join(buildDirParts[:i-1]...)
				return nil

			}
		}
	}

	return nil
}

func attemptRepro(ctx context.Context, binary, out string, useVCS bool, binVer semver.Version, env, buildArgs, buildFiles []string, dockerInfo *dockerBuildInfo) error {
	sort.Strings(buildArgs)
	buildArgs = append([]string{"build"}, buildArgs...)

	// if we're building inside a docker container we need to mount
	// the dir of the original binary so we can write the new binary
	// there
	var outputDir string
	if dockerInfo != nil {
		dir, file := filepath.Split(out)
		out = "/gorepro-output/" + file
		dir, err := filepath.Abs(dir)
		if err != nil {
			return fmt.Errorf("getting absolute path of output directory: %w", err)
		}
		outputDir = dir
	}
	if dryRun {
		buildArgs = append(buildArgs, fmt.Sprintf(`-o=%q`, out))
	} else {
		buildArgs = append(buildArgs, fmt.Sprintf("-o=%s", out))
	}

	if len(buildFiles) != 0 {
		buildArgs = append(buildArgs, buildFiles...)
	}
	if goDebug {
		// this will print extremely detailed info on what inputs are going
		// into build IDs, very useful for debugging why builds won't reproduce
		env = append(env, "GODEBUG=gocachehash=1")
	}
	if noGoGC {
		env = append(env, "GOGC=off")
	}

	if dockerInfo == nil && dryRun {
		sort.Strings(env)
		fmt.Printf("%s go %s\n", strings.Join(env, " "), strings.Join(buildArgs, " "))
		return nil
	}

	if dockerInfo != nil {
		if _, err := exec.LookPath("docker"); err != nil {
			return fmt.Errorf(`error finding "docker": %w`, err)
		}

		image := fmt.Sprintf("golang:%s-alpine", binVer)
		// build a Go docker image with git if necessary
		if useVCS {
			image = fmt.Sprintf("gorepro-local:%s", binVer)
			imageExists := true
			var exitError *exec.ExitError
			out, err := runCommand(ctx, "docker", "image", "inspect", image)
			if err != nil {
				if errors.As(err, &exitError) && bytes.Contains(out, []byte("No such image:")) {
					imageExists = false
				} else {
					return fmt.Errorf(`error running "docker image inspect: %w`, err)
				}
			}

			if !imageExists {
				infof("%q was built with embedded Git information, building Go docker image with Git installed", binary)
				cmd := exec.Command("docker", "build", "-t", image, "-")
				cmd.Stdin = strings.NewReader(fmt.Sprintf(dockerfileTmpl, binVer))
				cmd.Stdout = os.Stderr
				cmd.Stderr = os.Stderr
				verbosef("running command: %s", cmd)
				err := cmd.Run()
				if err != nil {
					return fmt.Errorf("building docker container: %w", err)
				}
			}
		}

		// TODO: don't do when dryrunning
		tempDir, err := os.MkdirTemp("", "*")
		if err != nil {
			return fmt.Errorf("creating temporary directory: %w", err)
		}
		defer func() {
			if err := os.RemoveAll(tempDir); err != nil {
				if errors.Is(err, os.ErrPermission) {
					removeCacheDirs(tempDir)
				} else {
					warnf("error removing temporary directory: %v", err)
				}
			}
		}()

		if dryRun {
			env = append(env, fmt.Sprintf("GOMODCACHE=%q", dockerInfo.goModCache))
		} else {
			env = append(env, fmt.Sprintf("GOMODCACHE=%s", dockerInfo.goModCache))
		}
		goEnvModCache, err := runCommand(ctx, "go", "env", "GOMODCACHE")
		if err != nil {
			return fmt.Errorf(`error running "go env": %s %w`, goEnvModCache, err)
		}
		ourGoModCache := string(trimNewline(goEnvModCache))
		if ourGoModCache != "" {
			if _, err := os.Stat(ourGoModCache); err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("reading directory: %w", err)
				}
				ourGoModCache = ""
			}
		}

		if dryRun {
			env = append(env, fmt.Sprintf("GOCACHE=%q", dockerGoBuildCache))
		} else {
			env = append(env, fmt.Sprintf("GOCACHE=%s", dockerGoBuildCache))
		}
		goEnvCache, err := runCommand(ctx, "go", "env", "GOCACHE")
		if err != nil {
			return fmt.Errorf(`error running "go env": %s %w`, goEnvCache, err)
		}
		ourGoCache := string(trimNewline(goEnvCache))
		if ourGoCache != "" {
			if _, err := os.Stat(ourGoCache); err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("reading directory: %w", err)
				}
				ourGoCache = ""
			}
		}

		sort.Strings(env)

		if dryRun {
			var cacheVolumes string
			if ourGoModCache != "" {
				cacheVolumes += fmt.Sprintf(" -v %q:%q", ourGoModCache, dockerInfo.goModCache)
			}
			if ourGoCache != "" {
				cacheVolumes += fmt.Sprintf(" -v %q:%q", ourGoCache, dockerGoBuildCache)
			}

			fmt.Printf("docker run -e %s -w %q%s -v %q:%q -v %q:/gorepro-output --rm %s go %s\n",
				strings.Join(env, " -e "),
				dockerInfo.buildDir,
				cacheVolumes,
				dockerInfo.localCodeDir,
				dockerInfo.containerCodeDir,
				outputDir,
				image,
				strings.Join(buildArgs, " "),
			)
			return nil
		}

		dockerArgs := []string{
			"docker",
			"run",
		}
		for _, envVar := range env {
			dockerArgs = append(dockerArgs, "-e", envVar)
		}
		dockerArgs = append(dockerArgs, "-w", dockerInfo.buildDir)
		if ourGoModCache != "" {
			modCacheMount, err := buildOverlayMount(tempDir, "modcache", ourGoModCache, dockerInfo.goModCache)
			if err != nil {
				return err
			}

			dockerArgs = append(
				dockerArgs,
				"--mount",
				modCacheMount,
			)
		}
		if ourGoCache != "" {
			cacheMount, err := buildOverlayMount(tempDir, "cache", ourGoCache, dockerGoBuildCache)
			if err != nil {
				return err
			}

			dockerArgs = append(
				dockerArgs,
				"--mount",
				cacheMount,
			)
		}
		dockerArgs = append(
			dockerArgs,
			"-v",
			fmt.Sprintf("%s:%s", dockerInfo.localCodeDir, dockerInfo.containerCodeDir),
			"-v",
			fmt.Sprintf("%s:/gorepro-output", outputDir),
		)
		dockerArgs = append(
			dockerArgs,
			"--rm",
			image,
			"go",
		)
		buildArgs = append(dockerArgs, buildArgs...)
	} else {
		for _, envVar := range goEnvVars {
			env = append(env, fmt.Sprintf("%s=%s", envVar, os.Getenv(envVar)))
		}

		buildArgs = append([]string{"go"}, buildArgs...)
	}

	// compile a new binary
	infof("building new binary...")
	cmd := exec.Command(buildArgs[0], buildArgs[1:]...)
	cmd.Env = env
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	verbosef("running command: %s", cmd)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("building: %w", err)
	}

	return nil
}

// go mod cache dirs are set to be read only, have to change perms before
// they can be removed
func removeCacheDirs(tempDir string) {
	err := filepath.WalkDir(tempDir, func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if de.IsDir() {
			return os.Chmod(path, 0o770)
		}
		if err := os.Chmod(path, 0o770); err != nil {
			return err
		}

		return os.Remove(path)
	})
	if err != nil {
		warnf("error removing temporary files: %v", err)
		return
	}
	if err := os.RemoveAll(tempDir); err != nil {
		warnf("error removing temporary directory: %v", err)
	}
}

// build a docker volume mount that is copy-on-write to avoid messing
// up local Go caches; docker will create directories as root sometimes
// making "go clean" commands not work correctly
// if someone knows a better/simpler way of doing this please let me know
func buildOverlayMount(tempDir, prefix, src, dst string) (string, error) {
	upperDir := filepath.Join(tempDir, prefix+"-upper")
	if err := os.Mkdir(upperDir, 0o755); err != nil {
		return "", fmt.Errorf("creating directory: %w", err)
	}
	workDir := filepath.Join(tempDir, prefix+"-work")
	if err := os.Mkdir(workDir, 0o755); err != nil {
		return "", fmt.Errorf("creating directory: %w", err)
	}

	return fmt.Sprintf(
		`type=volume,dst=%s,volume-driver=local,volume-opt=type=overlay,"volume-opt=o=lowerdir=%s,upperdir=%s,workdir=%s",volume-opt=device=overlay2`,
		dst,
		src,
		upperDir,
		workDir,
	), nil
}

// onlyBuildIDDifferent returns true if the only bytes that differ
// between origFile and newFile are the build IDs.
func onlyBuildIDDifferent(origFile, newFile *os.File, origBuildID, newBuildID []byte) (bool, error) {
	origr := bufio.NewReader(origFile)
	newr := bufio.NewReader(newFile)

	origIdx, err := findBuildID(origr, origBuildID)
	if err != nil {
		return false, err
	}
	if _, err = origFile.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	origr.Reset(origFile)
	newIdx, err := findBuildID(newr, newBuildID)
	if err != nil {
		return false, err
	}
	if _, err = newFile.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	newr.Reset(newFile)

	if origIdx != newIdx {
		return false, nil
	}

	buildIDIndex := origIdx
	buildIDLen := len(origBuildID)
	i := 0
	for {
		if i == buildIDIndex {
			if _, err := origr.Discard(buildIDLen); err != nil {
				return false, err
			}
			if _, err := newr.Discard(buildIDLen); err != nil {
				return false, err
			}
		}

		b1, err := origr.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				// reached end of file and no differences found, return true
				return true, nil
			}
			return false, err
		}
		b2, err := newr.ReadByte()
		if err != nil {
			// don't check for EOF here, the original file is read first
			// and if we hit an EOF here before reading from the original
			// file, that is an error since we know they are the same size
			return false, err
		}

		if b1 != b2 {
			return false, nil
		}
		i++
	}
}

// findBuildID returns the where the binary's build ID starts.
func findBuildID(r *bufio.Reader, buildID []byte) (int, error) {
	var cur int
	var i int

	for {
		b, err := r.ReadByte()
		if err != nil {
			return -1, err
		}
		if b == buildID[i] {
			i++
			if i == len(buildID)-1 {
				return cur - len(buildID), nil
			}
		} else {
			i = 0
		}

		cur++
	}
}
