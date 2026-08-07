# Releasing

Relaybox releases are built and verified by GitHub Actions from tags matching `v*`. Do not create release assets by hand.

## Pre-tag checks

1. Confirm the protected `main` branch is green, including quality, Linux/macOS/Windows native tests, container smoke, release validation, and CodeQL.
2. Confirm the version follows semantic versioning and the tag points to the intended protected commit.
3. Rehearse the release locally when GoReleaser and the host toolchain are available:

   ```sh
   go run github.com/goreleaser/goreleaser/v2@v2.17.1 release --snapshot --clean --skip=publish
   go run ./cmd/releasecheck -dist dist
   ```

4. Review generated release notes and any security-impacting changes before pushing the tag.

## Publication gates

The release workflow builds without publishing first. `releasecheck` then requires exactly six archives: Linux, macOS, and Windows for `amd64` and `arm64`. It verifies the exact checksum manifest, fully reads every required archive entry, checks ZIP CRCs, rejects missing or unexpected content, parses every executable format and architecture, and runs the host-native binary to confirm its embedded version. Every archive must contain the project license, README, and third-party notices.

The workflow also builds and restart-tests the non-root container, checks its embedded version and CA roots, generates source and image SBOMs, and blocks high or critical fixed vulnerabilities. It binds the exact release files and saved container image into one hashed handoff. Only after those gates pass does it attest the release files, push the saved image under a content- and run-bound `build-$GITHUB_SHA-$BUNDLE_PREFIX-$RUN_ID-$ATTEMPT` staging tag, sign and attest that digest, promote the same digest to the release tag, and create the public GitHub release. Tags containing a semantic-version prerelease suffix are published as GitHub prereleases. The workflow refuses to rebuild an existing GitHub release and never overwrites an existing staging tag or a release image tag that points to another digest.

GitHub Container Registry packages can be private when first created. Before the first public release, open the `relaybox` package settings, change its visibility to **Public**, and confirm the change. The workflow deliberately stops before creating a public GitHub release unless both the package API reports public visibility and an anonymous pull resolves the release tag to the exact verified digest. If this is the only failure, make the package public and rerun the failed `publish-release` job; the already signed and attested image digest is unchanged.

Each `build-$GITHUB_SHA-$BUNDLE_PREFIX-$RUN_ID-$ATTEMPT` tag is retained as an immutable audit reference; a retry uses a new attempt suffix instead of overwriting it. If publication fails after a staging tag is pushed, investigate and rerun the failed workflow jobs: the verified bundle and digest checks prevent a different build from being substituted. Delete an abandoned staging tag only after confirming that no release tag or release refers to its digest. If the source tag is moved, no longer descends from protected `main`, or already has a GitHub release, the workflow refuses to continue; create a new valid tag rather than bypassing that check.

## Consumer verification

Download the release assets and verify checksums before installation:

```sh
sha256sum --check checksums.txt
gh attestation verify relaybox_VERSION_OS_ARCH.tar.gz --repo 1337lean/relaybox
```

Windows archives use `.zip`. GitHub's attestation command can also verify `checksums.txt` and the SBOM files. Verify the container by immutable digest when deploying it.
