# Versioning and releases

This project follows [Semantic Versioning 2.0.0](https://semver.org).

## The rules

A version is `MAJOR.MINOR.PATCH`.

- **MAJOR** — incompatible change to the public API: the CLI flags, the
  HTTP routes or their response shapes, the module path.
- **MINOR** — new backward-compatible functionality: a new command, a new
  endpoint, a new flag.
- **PATCH** — backward-compatible bug fixes.

Additional labels rotate around the core:

- Pre-release: `1.0.0-alpha`, `1.0.0-alpha.1`, `1.0.0-rc.1`. These have
  **lower** precedence than the release they lead to.
- Build metadata: `1.0.0+build.5`. Ignored when comparing versions.

Precedence, from the spec:

```
1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta
  < 1.0.0-beta < 1.0.0-beta.2 < 1.0.0-beta.11
  < 1.0.0-rc.1 < 1.0.0
```

## The `v` prefix

`v1.2.3` is **not** a semantic version. It is a tag name that happens to
contain one. The semantic version is `1.2.3`; the leading `v` is a Git
convention.

This matters here:

- Git tags are written `v1.2.3`.
- The version compiled into the binary is `1.2.3` — the prefix is stripped
  and build metadata is dropped, because metadata does not affect
  precedence.

```console
$ ./wv -version
wv 1.2.3 (commit a1b2c3d, built 2026-10-17T00:00:00Z, go1.27.1 linux/amd64)
```

## Cutting a release

1. Make sure `main` is green.
2. Tag it. The `Makefile` validates the version before tagging:

   ```console
   $ make tag VERSION=1.2.0
   ```

   That runs `git tag -a v1.2.0` and pushes it. For a pre-release:

   ```console
   $ make tag VERSION=1.3.0-rc.1
   ```

3. The `release` workflow runs on the tag, builds every platform, and
   publishes a GitHub release. A tag with a pre-release identifier becomes
   a GitHub pre-release automatically.

Nothing in the source is hand-edited for a version bump — the version is
read from the tag at build time.

## Local builds

```console
$ make version          # what this tree would build
$ make build            # bin/ for the host platform
$ make release          # dist/ for every platform + checksums.txt
$ make snapshot         # release with a prerelease version
```

`make release` derives the version from `git describe`:

- on an exact tag `v1.2.3` → version `1.2.3`
- otherwise → `0.0.0-dev.<short-sha>`, still valid semver

Override with `make release VERSION=1.2.3`. The version is validated
against the spec grammar first; a malformed one fails the build.

## Platforms

```
linux    amd64 arm64 arm(armv7) 386
darwin   amd64 arm64
windows  amd64 arm64
freebsd  amd64
```

Binaries are named `<command>_<version>_<os>_<arch>`, with `.exe` on
Windows. Every release ships `checksums.txt`:

```console
$ sha256sum -c checksums.txt
```

## CI

- `ci.yml` — on every push and pull request: `gofmt`, `go vet`, tests with
  the race detector, a native build, and a cross-compile of the whole
  platform matrix. A broken platform combination fails CI rather than the
  release.
- `release.yml` — on a `v*` tag: validates the tag against the semver
  grammar, cross-compiles all platforms, verifies the injected version,
  and publishes the release with checksums.

Builds use `-trimpath` and `CGO_ENABLED=0`, so binaries are static and
paths from the build machine do not leak into them.
