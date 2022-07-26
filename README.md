# gorepro

`go install github.com/capnspacehook/gorepro@latest`

Reproduce Go binaries by recreating and running the commands that produced them. Requires Go 1.18 or later.

`gorepro [flags] binary`

## Purpose

Verifying pre-compiled binaries of open source projects is important from a security prospective. While you can easily inspect the source code for backdoors or
malicious flaws, it can be difficult to verify the validity of distributed binaries. By manually creating a binary and comparing it to the official binary, you can verify that the official binary was indeed created from the published source code.

Go makes it fairly easy to reproduce binaries, but it is still not always simple. Gorepro aims to make the process as easy as possible. Simply give it a Go binary and it will attempt to recreate the exact same binary, bit for bit.

## Mechanism

Gorepro recreates the `go build` command that produced a specified binary by reading the embedded build metadata that Go 1.18 and newer includes by default. Gorepro also
downloads and uses the same version of Go that was used to create the binary if it is not already present on your system. If the binary also has embedded version control system (VCS) information, gorepro will try to ensure your build environment is compatible with what the binary was created with. After the new binary is built, gorepro hashes both the original and new binaries with SHA-256 and compares the hashes to ensure they are the exact same.

Gorepro assumes and requires that the directory it is run in contains the source code used to build the specified binary. The binary to reproduce does not need to be in any specified directory though.

## Troubleshooting

If gorepro detects a problem that prevents reproducibility that it can't fix, it will notify you and tell you how to fix it.
However, gorepro can't detect everything, and some fixes aren't intuitive (looking at you, unset `-trimpath`).

### Manually passing Go files

Gorepro will fail if the binary you're trying to reproduce had Go files passed to the `go build` command that created it and you didn't pass the same files via `-f`, or vice versa. Yes, `go build -o mybin` and `go build -o mybin main.go` will produce slightly different binaries for some reason.

For example, if a binary was built by running `CGO_ENABLED=0 go build -trimpath -o mybin main.go`, you can reproduce the binary by running `gorepro -f main.go mybin`.

### Undetected build flags

Currently [-buildmode isn't included in build metadata](https://github.com/golang/go/issues/53856), though that should change for Go 1.20. In any case, you may find that the command gorepro generates to reproduce a binary is missing flags that were included in the original build. If that's the case, you can pass the missing flags like so: `gorepro -b="-buildmode=pie -ldflags=-s" mybin`.

### -trimpath not set

If you are trying to reproduce a binary that wasn't compiled with `-trimpath` set, most of the time gorepro will be able to detect this and tell you how to reproduce the build anyway. To reproduce you'll need to:

- Ensure the `GOROOT` environmental variable has the same value as when the original binary was created.
  - If the binary was built with the same version of Go that is installed locally, you can do this by copying the contents of your current `GOROOT` to where gorepro tells you to, and then setting `GOROOT` appropriately before running gorepro again.
  - Otherwise, gorepro will try to download and use the correct version of Go, which won't have the same `GOROOT` as your main version of Go. You'll have to copy the `GOROOT` of the appropriate Go version to where gorepo tells you to, and then set `GOROOT` by running `go<version> -w GOROOT=<GOROOT>`. This will change the `GOROOT` for only that specific version of Go, not affecting any other installed versions on your system.
- Copy the source code to the directory specified by gorepro and run gorepro in that directory.

## Caveats

- Reproducing binaries built with `CGO_ENABLED=1` is not supported. Reproducing C/C++ code is a whole can of worms I'm not even going to attempt to try.
- Git is the only VCS that gorepro supports. Reproducing binaries built that use other VCSes is possible using gorepro, but build environment checks will not be run.
- Only reproducing binaries built by the official Go compiler `gc` and the official Go toolchain is supported. I may support the `gccgo` compiler in the future if the need arises, but I'm unsure whether I'd want to support TinyGo or other Go implementations.

## Creating easily reproducible binaries

- If at all possible, set `CGO_ENABLED=0` when building. Pure Go binaries are much easier to reproduce.
- Always set `-trimpath`. There is no reason not to for production builds. Not doing so requires users who wish to reproduce your binary to build from the exact same directory path you did, and use the exact same `GOROOT`.
- Document the process used to create the binary, or better yet publish the code that produced it. Gorepro can detect most flags or environmental variables used, but cannot detect all depending on what version of Go was used to build the binary.
