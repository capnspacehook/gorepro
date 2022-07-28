package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/fatih/color"
	"github.com/goretk/gore"
)

// TODO: GODEBUG=gocachehash=1 when verbose

const (
	cmdLinePkg      = "command-line-arguments"
	goVersionPrefix = "go version go"
)

var (
	infoColor    = color.New(color.FgBlue)
	warnColor    = color.New(color.FgYellow)
	errColor     = color.New(color.FgRed)
	almostColor  = color.New(color.FgMagenta)
	successColor = color.New(color.FgGreen)

	additionalFlags string
	dryRun          bool
	goCommand       string
	verbose         bool

	goEnvVars = []string{
		"GOCACHE",
		"GOMODCACHE",
		"GOPATH",
		"GOROOT",
		"GOPROXY",
		"HOME",
		"PATH",
	}

	failReasons []string
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
install and use the appropriate Go version to reproduce the specified
binary. Note that gorepro requires that binaries to reproduce be built
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

func addFailReason(format string, a ...any) {
	failReasons = append(failReasons, fmt.Sprintf(format, a...))
}

func infof(format string, a ...any) {
	if !verbose {
		return
	}
	infoColor.Fprintf(os.Stderr, format, a...)
	infoColor.Fprint(os.Stderr, "\n")
}

func warnf(format string, a ...any) {
	warnColor.Fprintf(os.Stderr, format, a...)
	warnColor.Fprint(os.Stderr, "\n")
}

func errf(format string, a ...any) {
	errColor.Fprintf(os.Stderr, format, a...)
	errColor.Fprint(os.Stderr, "\n")
}

func almostf(format string, a ...any) {
	almostColor.Fprintf(os.Stderr, format, a...)
	almostColor.Fprint(os.Stderr, "\n")
}

func successf(format string, a ...any) {
	successColor.Fprintf(os.Stderr, format, a...)
	successColor.Fprint(os.Stderr, "\n")
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

func getBuildID(goBin, file string) ([]byte, error) {
	return runCommand(goBin, "tool", "buildid", file)
}

func runCommand(name string, arg ...string) ([]byte, error) {
	cmd := exec.Command(name, arg...)
	infof("running command: %s", cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	return out, nil
}

func main() {
	retCode, err := mainErr()
	if err != nil {
		errf("%v", err)
	}
	if retCode == 2 {
		warnf("reasons reproducing may have failed:")
		for _, reason := range failReasons {
			warnf(" - %s", reason)
		}
	}
	os.Exit(retCode)
}

func mainErr() (int, error) {
	flag.Usage = usage
	flag.StringVar(&additionalFlags, "b", "", "extra build flags that are needed to reproduce but aren't detected, comma separated")
	flag.BoolVar(&dryRun, "d", false, "print build commands instead of running them")
	flag.StringVar(&goCommand, "g", "", `Path to "go" command to use to build`)
	flag.BoolVar(&verbose, "v", false, "print commands being run and verbose information")
	flag.Parse()

	var extraFlags []string
	if len(additionalFlags) != 0 {
		extraFlags = strings.Split(additionalFlags, ",")
	}

	// ensure the go command is present
	goCmd := "go"
	if goCommand != "" {
		goCmd = goCommand
	}
	if _, err := exec.LookPath(goCmd); err != nil {
		return 1, fmt.Errorf(`could not find %q: %v`, goCmd, err)
	}

	if flag.NArg() == 0 {
		usage()
		return 1, nil
	} else if flag.NArg() > 1 {
		fmt.Fprintf(os.Stderr, "only one binary can be reproduced at a time\n\nusage:\n\n")
		usage()
		return 1, nil
	}
	binary := flag.Arg(0)

	// read the binary's build info
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		return 1, fmt.Errorf("error parsing build metadata: %v", err)
	}
	binVersionStr := info.GoVersion
	if len(binVersionStr) > 2 {
		binVersionStr = binVersionStr[2:]
	}
	binVer, err := parseVersion(binVersionStr)
	if err != nil {
		return 1, fmt.Errorf("error parsing go version of %q: %v", binary, err)
	}
	// check if binary can be reproduced
	if binVer.Minor < 18 {
		return 1, fmt.Errorf("%q was built with go%s, only go1.18 or newer embeds build metadata that is required by gorepro",
			binary,
			binVersionStr,
		)
	}
	if len(info.Settings) == 0 {
		return 1, fmt.Errorf("no build metadata present in %q, reproducing is possible but not supported by gorepro", binary)
	}

	file, err := gore.Open(binary)
	if err != nil {
		return 1, err
	}
	defer file.Close()

	// check if source files for the main module need to be explicitly
	// passed
	var mainSrcFiles []string
	if info.Path == cmdLinePkg {
		p, err := file.GetPackages()
		if err != nil {
			return 1, err
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
		return 1, fmt.Errorf(`%q was built using "go install", reproducing is possible but not supported by gorepro`, binary)
	}

	// ensure main module source files exist
	if len(mainSrcFiles) != 0 {
		for _, file := range mainSrcFiles {
			if _, err := os.Stat(file); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return 1, fmt.Errorf(`%q was built by passing %q to "go build", but that file couldn't be found; rerun gorepro in the directory with %q`,
						binary,
						file,
						file,
					)
				}
				return 1, fmt.Errorf("error reading build file: %v", err)
			}
		}
	}

	// get the version of the go command, we may have to download
	// a different version if it's not available
	out, err := runCommand(goCmd, "version")
	if err != nil {
		return 1, fmt.Errorf(`error running "go version": %v`, err)
	}

	if len(out) < len(goVersionPrefix) {
		return 1, fmt.Errorf(`malformed "go version" output`)
	}
	out = out[len(goVersionPrefix):]
	i := bytes.IndexByte(out, ' ')
	if i == -1 {
		return 1, fmt.Errorf(`malformed "go version" output`)
	}
	goVersionStr := string(out[:i])

	goVer, err := parseVersion(goVersionStr)
	if err != nil {
		return 1, fmt.Errorf("error parsing go version: %v", err)
	}

	goBin := goCmd
	if binVersionStr != goVersionStr {
		if goCommand != "" {
			return 1, fmt.Errorf("%q was built with go%s but you specified %q to be used which is go%s",
				binary,
				binVersionStr,
				goCommand,
				goVersionStr,
			)
		}

		goBin = "go" + binVersionStr
		// if the required version of Go is available we don't need to download it
		_, err := exec.LookPath(goBin)
		if err != nil {
			// Go 1.16 added support for installing packages with a version suffix
			if goVer.Minor < 16 {
				return 1, fmt.Errorf("go1.16 or newer is required to install packages in module aware mode, go%s is installed",
					goVersionStr,
				)
			}

			// the version of Go the binary was built with isn't installed,
			// install it
			pkg := fmt.Sprintf("golang.org/dl/%s@latest", goBin)
			if dryRun {
				fmt.Printf("go install %s\n%s download\n", pkg, goBin)
			} else {
				infof("installing %s", goBin)
				out, err := runCommand("go", "install", pkg)
				if err != nil {
					return 1, fmt.Errorf("error installing %s: %s %v", goBin, out, err)
				}

				out, err = runCommand(goBin, "download")
				if err != nil {
					return 1, fmt.Errorf("error downloading %s: %s %v", goBin, out, err)
				}
			}
		}
	}

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
		case "-asmflags", "-gcflags", "-ldflags", "-tags":
			if setting.Key == "ldflags" {
				if strings.Contains(setting.Value, "-buildid") {
					buildIDExplicitlySet = true
				}
			}

			if dryRun {
				buildArgs = append(buildArgs, fmt.Sprintf(`%s="%s"`, setting.Key, setting.Value))
			} else {
				buildArgs = append(buildArgs, fmt.Sprintf("%s=%s", setting.Key, setting.Value))
			}
		case "-compiler":
			if setting.Value != "gc" {
				// TODO: test with gccgo
				return 1, fmt.Errorf("Go compiler %s was used to build %s, only the building with the official Go compiler gc is supported",
					setting.Value,
					binary,
				)
			}
		case "-trimpath":
			trimpathFound = true
			buildArgs = append(buildArgs, setting.Key)
		case "vcs":
			vcsUsed = setting.Value
		case "vcs.modified":
			if setting.Value == "true" {
				vcsModified = true
				addFailReason("the Git repo %q was built in had uncommitted file(s) when it was built, you may be trying to build with different source code",
					binary,
				)
			}
		case "vcs.revision":
			vcsRev = setting.Value
		case "CGO_ENABLED":
			if setting.Value != "0" {
				return 1, fmt.Errorf("%s was built with cgo enabled, reproducing is possible but not supported by gorepro", binary)
			}
			env = append(env, "CGO_ENABLED=0")
		case "GOAMD64", "GOARCH", "GOARM", "GOEXPERIMENT", "GOMIPS", "GOMIPS64", "GOOS", "GOPPC64", "GOWASM":
			env = append(env, fmt.Sprintf("%s=%s", setting.Key, setting.Value))
		}
	}

	if !trimpathFound {
		setTrimpath, err := checkTrimpath(binVer, file, goBin, binary, info)
		if err != nil {
			return 1, err
		}
		if setTrimpath {
			buildArgs = append(buildArgs, "-trimpath")
		}
	}

	if vcsUsed != "" {
		tempFile, err := checkVCS(vcsUsed, vcsRev, vcsModified, binary)
		if err != nil {
			return 1, err
		}
		defer os.Remove(tempFile)
	} else {
		buildArgs = append(buildArgs, "-buildvcs=false")
	}

	if len(extraFlags) != 0 {
		buildArgs = append(buildArgs, extraFlags...)
	}

	ourBinary := binary + ".repro"
	sort.Strings(buildArgs)
	buildArgs = append([]string{"build"}, buildArgs...)
	if dryRun {
		buildArgs = append(buildArgs, fmt.Sprintf(`-o="%s"`, ourBinary))
	} else {
		buildArgs = append(buildArgs, fmt.Sprintf("-o=%s", ourBinary))
	}
	if len(mainSrcFiles) != 0 {
		buildArgs = append(buildArgs, mainSrcFiles...)
	}

	if dryRun {
		sort.Strings(env)
		fmt.Printf("%s %s %s\n", strings.Join(env, " "), goBin, strings.Join(buildArgs, " "))
		return 0, nil
	}

	for _, envVar := range goEnvVars {
		env = append(env, fmt.Sprintf("%s=%s", envVar, os.Getenv(envVar)))
	}

	// compile a new binary
	cmd := exec.Command(goBin, buildArgs...)
	cmd.Env = env
	infof("running command: %s", cmd)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return 1, fmt.Errorf("error building: %s %v", out, err)
	}

	// check that file sizes match
	binfi, err := os.Stat(binary)
	if err != nil {
		return 1, fmt.Errorf("error reading file: %v", err)
	}
	ourBinfi, err := os.Stat(ourBinary)
	if err != nil {
		return 1, fmt.Errorf("error reading file: %v", err)
	}

	if binfi.Size() != ourBinfi.Size() {
		return 2, fmt.Errorf("failed to reproduce: file sizes don't match")
	}

	// check that file hashes match
	binf, err := os.Open(binary)
	if err != nil {
		return 1, fmt.Errorf("error opening file: %v", err)
	}
	defer binf.Close()
	ourBinf, err := os.Open(ourBinary)
	if err != nil {
		return 1, fmt.Errorf("error opening file: %v", err)
	}
	defer ourBinf.Close()

	binHash := sha256.New()
	if _, err := io.Copy(binHash, binf); err != nil {
		return 1, fmt.Errorf("error hashing %q: %v", binary, err)
	}
	ourBinHash := sha256.New()
	if _, err := io.Copy(ourBinHash, ourBinf); err != nil {
		return 1, fmt.Errorf("error hashing %q: %v", ourBinary, err)
	}
	if !bytes.Equal(binHash.Sum(nil), ourBinHash.Sum(nil)) {
		errf("failed to reproduce: file hashes don't match")
		// if the build ID was explicitly set via a linker flag, don't
		// check the differences between build IDs, they will be the same
		if buildIDExplicitlySet {
			return 2, nil
		}

		binBuildID, err := getBuildID(goBin, binary)
		if err != nil {
			return 2, fmt.Errorf("error getting build ID of %q: %v", binary, err)
		}
		if _, err := binf.Seek(0, io.SeekStart); err != nil {
			return 2, fmt.Errorf("error seeking to beginning of %q: %v", binary, err)
		}
		ourBinBuildID, err := getBuildID(goBin, ourBinary)
		if err != nil {
			return 2, fmt.Errorf("error getting build ID of %q: %v", ourBinary, err)
		}
		if _, err := ourBinf.Seek(0, io.SeekStart); err != nil {
			return 2, fmt.Errorf("error seeking to beginning of %q: %v", ourBinary, err)
		}

		// if the build IDs are different but the rest of the binaries
		// match tell the user
		restSame, err := onlyBuildIDDifferent(binf, ourBinf, binBuildID, ourBinBuildID)
		if err != nil {
			return 2, fmt.Errorf("error comparing binaries: %v", err)
		}

		if restSame {
			almostf("however, only the build ID differs between binaries, binaries are almost the same")
		} else {
			binBuildIDParts := bytes.Split(binBuildID, []byte("/"))
			ourBinBuildIDParts := bytes.Split(ourBinBuildID, []byte("/"))

			if bytes.Equal(binBuildIDParts[2], ourBinBuildIDParts[2]) {
				almostf("the main module's compiled code is the same between binaries")
			}
		}

		return 2, nil
	}

	successf("reproduced successfully! new binary is at %q", ourBinary)

	return 0, nil
}

func checkTrimpath(binVer semver.Version, file *gore.GoFile, goBin, binary string, info *debug.BuildInfo) (bool, error) {
	// Go 1.19+ add -trimpath to the build metadata, on earlier Go
	// versions we can't always know for sure if it was passed
	trimpathUnknown := true
	if binVer.Minor >= 19 {
		trimpathUnknown = false
	}

	// detect if -trimpath was passed by inspecting the binary's GOROOT
	goroot, err := file.GetGoRoot()
	if err != nil {
		if errors.Is(err, gore.ErrNoGoRootFound) {
			// if we don't know if -trimpath was set
			if trimpathUnknown {
				addFailReason(`"-trimpath" may not have been set when building %q, it could not be detected from embedded build metadata`,
					binary,
				)
				return true, nil
			}
		} else {
			return false, fmt.Errorf("error finding GOROOT of %q: %v", binary, err)
		}
	}
	// GOROOT will be 'go' if -trimpath was set
	if goroot == "go" {
		return true, nil
	}
	// if we failed to find the GOROOT of the binary, skip this
	if goroot != "" {
		ourGoRoot, err := runCommand(goBin, "env", "GOROOT")
		if err != nil {
			return false, fmt.Errorf("error getting GOROOT of %s: %v", goBin, err)
		}
		if len(ourGoRoot) != 0 {
			ourGoRoot = ourGoRoot[:len(ourGoRoot)-1]
			if goroot != string(ourGoRoot) {
				return false, fmt.Errorf(`"-trimpath" was not set when building %q, and %q was used as GOROOT while your GOROOT is %q`,
					binary,
					goroot,
					ourGoRoot,
				)
			}
		}

		trimpathUnknown = false
	}

	// get the build dir the binary was built in
	pkgs, err := file.GetPackages()
	if err != nil {
		return false, fmt.Errorf("error getting packages of %q: %v", binary, err)
	}
	var buildDir string
	for _, pkg := range pkgs {
		if pkg.Name == "main" {
			buildDir = pkg.Filepath
			break
		}
	}

	cwd, err := os.Getwd()
	if err != nil {
		return false, err
	}
	if cwd != buildDir {
		if trimpathUnknown {
			addFailReason(`"-trimpath" may not have been set when building %q, and %q was used as the build directory while you are using %q`,
				binary,
				buildDir,
				cwd,
			)
		} else {
			return false, fmt.Errorf(`"-trimpath" was not set when building %q, and %q was used as the build directory while you are using %q`,
				binary,
				buildDir,
				cwd,
			)
		}
	}

	return false, nil
}

func checkVCS(vcsUsed, vcsRev string, vcsModified bool, binary string) (string, error) {
	var ok bool
	var tempFileName string
	// if we didn't return successfully and a temp file was created, delete
	// it so the caller doesn't have to worry about it
	defer func() {
		if tempFileName != "" && !ok {
			os.Remove(tempFileName)
		}
	}()

	if vcsUsed != "git" {
		addFailReason("version control system %s isn't supported by gorepro", vcsUsed)
		return "", nil
	}

	if _, err := exec.LookPath("git"); err != nil {
		return "", fmt.Errorf(`could not find "git": %v`, err)
	}
	gitStatus, err := runCommand("git", "status", "--porcelain=v1")
	if err != nil {
		return "", fmt.Errorf("error getting Git status: %s %v", gitStatus, err)
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
				return "", fmt.Errorf(`error parsing "git status --porcelain: line too short: %s`, txt)
			}
			_, file, ok := strings.Cut(txt[1:], " ")
			if !ok {
				return "", fmt.Errorf(`error parsing "git status --porcelain: line malformed: %s`, txt)
			}

			_, file = filepath.Split(file)
			if strings.HasSuffix(file, ".go") || file == "go.mod" || file == "go.sum" {
				addFailReason("there is at least one new or modified Go file in the local Git repo, source code may differ from what %q was built with",
					binary,
				)
				break
			}
		}
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf(`error parsing "git status" output: %v`, err)
		}
	}

	if vcsModified && len(gitStatus) == 0 {
		infof("%q was built in a dirty Git repo but the local Git repo is clean; creating a temporary file to make local Git repo dirty",
			binary,
		)
		tempFile, err := os.CreateTemp(".", "*")
		if err != nil {
			return "", fmt.Errorf("error creating temporary file: %v", err)
		}
		tempFileName = tempFile.Name()
		tempFile.Close()
	} else if !vcsModified && len(gitStatus) != 0 {
		return "", fmt.Errorf("%q was built in a clean Git repo, and the local Git repo isn't clean; reproducing will fail", binary)
	}

	gitShow, err := runCommand("git", "-c", "log.showsignature=false", "show", "-s", "--format=%H")
	if err != nil {
		return "", fmt.Errorf("error getting latest git commit: %s %v", gitShow, err)
	}
	// remove trailing newline
	latestCommit := string(gitShow[:len(gitShow)-1])
	if vcsRev != latestCommit {
		return "", fmt.Errorf("%q was built on commit %s, the latest commit in the local Git repo is %s; reproducing will fail",
			binary,
			vcsRev,
			latestCommit,
		)
	}

	ok = true

	return tempFileName, nil
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
