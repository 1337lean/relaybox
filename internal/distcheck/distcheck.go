// Package distcheck verifies that a Relaybox distribution is complete and
// internally consistent before any artifact is published.
package distcheck

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	maxChecksumBytes  = 1 << 20
	maxArchiveBytes   = 512 << 20
	maxArchiveEntries = 100
	maxEntryBytes     = 256 << 20
)

type target struct {
	os   string
	arch string
}

var expectedTargets = []target{
	{os: "darwin", arch: "amd64"},
	{os: "darwin", arch: "arm64"},
	{os: "linux", arch: "amd64"},
	{os: "linux", arch: "arm64"},
	{os: "windows", arch: "amd64"},
	{os: "windows", arch: "arm64"},
}

type archive struct {
	name    string
	path    string
	target  target
	version string
}

// Verify checks the exact release matrix, archive contents, executable
// formats, and checksum manifest. expectedVersion may have a leading v and may
// be empty for snapshot rehearsals. When smoke is true, the host-native binary
// is also executed.
func Verify(directory, expectedVersion string, smoke bool) error {
	if expectedVersion != "" {
		if strings.HasPrefix(expectedVersion, "v") {
			var err error
			expectedVersion, err = ValidateTag(expectedVersion)
			if err != nil {
				return err
			}
		} else if _, err := ValidateTag("v" + expectedVersion); err != nil {
			return err
		}
	}
	archives, version, err := discoverArchives(directory)
	if err != nil {
		return err
	}
	if expectedVersion != "" && version != expectedVersion {
		return fmt.Errorf("release version %q does not match expected version %q", version, expectedVersion)
	}
	if err := verifyChecksums(directory, archives); err != nil {
		return err
	}

	smoked := !smoke
	for _, item := range archives {
		executable, err := inspectArchive(item)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", item.name, err)
		}
		if smoke && item.target.os == runtime.GOOS && item.target.arch == runtime.GOARCH {
			if err := smokeExecutable(executable, version); err != nil {
				return fmt.Errorf("smoke %s: %w", item.name, err)
			}
			smoked = true
		}
	}
	if !smoked {
		return fmt.Errorf("no archive can run on verifier host %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return nil
}

// ValidateTag requires a v-prefixed Semantic Version 2.0.0 tag and returns
// the version without the v prefix.
func ValidateTag(tag string) (string, error) {
	if len(tag) < 2 || len(tag) > 128 || tag[0] != 'v' {
		return "", fmt.Errorf("release tag %q is not a bounded v-prefixed semantic version", tag)
	}
	version := tag[1:]
	if strings.Contains(version, "+") {
		return "", fmt.Errorf("release tag %q uses build metadata, which cannot be represented by a GHCR tag", tag)
	}
	coreAndPre := version
	core, prerelease, hasPrerelease := strings.Cut(coreAndPre, "-")
	if hasPrerelease {
		if err := validateSemverIdentifiers(prerelease, true); err != nil {
			return "", fmt.Errorf("release tag %q has invalid prerelease: %w", tag, err)
		}
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("release tag %q must contain major.minor.patch", tag)
	}
	for _, part := range parts {
		if !decimalIdentifier(part) || len(part) > 1 && part[0] == '0' {
			return "", fmt.Errorf("release tag %q has an invalid core version", tag)
		}
	}
	return version, nil
}

func validateSemverIdentifiers(value string, rejectNumericLeadingZero bool) error {
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" {
			return errors.New("identifier is empty")
		}
		for _, r := range identifier {
			if !(r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r == '-') {
				return errors.New("identifier contains a non-ASCII alphanumeric character")
			}
		}
		if rejectNumericLeadingZero && len(identifier) > 1 && identifier[0] == '0' && decimalIdentifier(identifier) {
			return errors.New("numeric identifier has a leading zero")
		}
	}
	return nil
}

func decimalIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func discoverArchives(directory string) ([]archive, string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, "", fmt.Errorf("read distribution: %w", err)
	}
	wanted := make(map[target]bool, len(expectedTargets))
	for _, expected := range expectedTargets {
		wanted[expected] = true
	}
	seen := make(map[target]bool, len(expectedTargets))
	var archives []archive
	version := ""
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tar.gz") && !strings.HasSuffix(entry.Name(), ".zip") {
			continue
		}
		item, ok := parseArchiveName(directory, entry.Name())
		if !ok || !wanted[item.target] {
			return nil, "", fmt.Errorf("unexpected release archive %q", entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			return nil, "", fmt.Errorf("inspect %q: %w", entry.Name(), err)
		}
		if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxArchiveBytes {
			return nil, "", fmt.Errorf("release archive %q is not a bounded regular file", entry.Name())
		}
		if seen[item.target] {
			return nil, "", fmt.Errorf("duplicate release target %s/%s", item.target.os, item.target.arch)
		}
		seen[item.target] = true
		if version == "" {
			version = item.version
		} else if item.version != version {
			return nil, "", fmt.Errorf("archive %q has version %q, want %q", item.name, item.version, version)
		}
		archives = append(archives, item)
	}
	for _, expected := range expectedTargets {
		if !seen[expected] {
			return nil, "", fmt.Errorf("missing release archive for %s/%s", expected.os, expected.arch)
		}
	}
	sort.Slice(archives, func(i, j int) bool { return archives[i].name < archives[j].name })
	return archives, version, nil
}

func parseArchiveName(directory, name string) (archive, bool) {
	if !strings.HasPrefix(name, "relaybox_") {
		return archive{}, false
	}
	for _, candidate := range expectedTargets {
		extension := ".tar.gz"
		if candidate.os == "windows" {
			extension = ".zip"
		}
		suffix := "_" + candidate.os + "_" + candidate.arch + extension
		if !strings.HasSuffix(name, suffix) {
			continue
		}
		version := strings.TrimSuffix(strings.TrimPrefix(name, "relaybox_"), suffix)
		if version == "" {
			return archive{}, false
		}
		return archive{name: name, path: filepath.Join(directory, name), target: candidate, version: version}, true
	}
	return archive{}, false
}

func verifyChecksums(directory string, archives []archive) error {
	manifest, err := readBoundedRegular(filepath.Join(directory, "checksums.txt"), maxChecksumBytes)
	if err != nil {
		return fmt.Errorf("read checksums.txt: %w", err)
	}
	wanted := make(map[string]archive, len(archives))
	for _, item := range archives {
		wanted[item.name] = item
	}
	seen := make(map[string]bool, len(archives))
	lines := strings.Split(strings.TrimSpace(string(manifest)), "\n")
	if len(lines) != len(archives) {
		return fmt.Errorf("checksums.txt contains %d entries, want %d", len(lines), len(archives))
	}
	for lineNumber, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return fmt.Errorf("checksums.txt line %d is invalid", lineNumber+1)
		}
		digest, err := hex.DecodeString(fields[0])
		if err != nil || len(digest) != sha256.Size {
			return fmt.Errorf("checksums.txt line %d has an invalid SHA-256", lineNumber+1)
		}
		name := strings.TrimPrefix(fields[1], "*")
		if filepath.Base(name) != name || name == "." {
			return fmt.Errorf("checksums.txt line %d has an unsafe name", lineNumber+1)
		}
		item, ok := wanted[name]
		if !ok {
			return fmt.Errorf("checksums.txt contains unexpected artifact %q", name)
		}
		if seen[name] {
			return fmt.Errorf("checksums.txt repeats artifact %q", name)
		}
		seen[name] = true
		actual, err := fileSHA256(item.path)
		if err != nil {
			return fmt.Errorf("hash %q: %w", name, err)
		}
		if !strings.EqualFold(fields[0], hex.EncodeToString(actual[:])) {
			return fmt.Errorf("checksum mismatch for %q", name)
		}
	}
	for name := range wanted {
		if !seen[name] {
			return fmt.Errorf("checksums.txt is missing %q", name)
		}
	}
	return nil
}

func readBoundedRegular(name string, limit int64) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		file.Close()
		return nil, errors.New("file is not a bounded regular file")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(data)) > limit {
		return nil, errors.New("file exceeds verification limit")
	}
	return data, nil
}

func fileSHA256(name string) ([sha256.Size]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxArchiveBytes {
		file.Close()
		if err != nil {
			return [sha256.Size]byte{}, err
		}
		return [sha256.Size]byte{}, errors.New("artifact is not a bounded regular file")
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return [sha256.Size]byte{}, copyErr
	}
	if closeErr != nil {
		return [sha256.Size]byte{}, closeErr
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func inspectArchive(item archive) ([]byte, error) {
	required := map[string]bool{
		"LICENSE":                false,
		"README.md":              false,
		"THIRD_PARTY_NOTICES.md": false,
	}
	executableName := "relaybox"
	if item.target.os == "windows" {
		executableName += ".exe"
	}
	required[executableName] = false

	var executable []byte
	visit := func(name string, mode os.FileMode, size int64, reader io.Reader) error {
		clean, err := cleanArchiveName(name)
		if err != nil {
			return err
		}
		if _, ok := required[clean]; !ok {
			return fmt.Errorf("archive contains unexpected entry %q", clean)
		}
		if required[clean] {
			return fmt.Errorf("archive repeats required entry %q", clean)
		}
		if mode&os.ModeSymlink != 0 || !mode.IsRegular() {
			return fmt.Errorf("required archive entry %q is not regular", clean)
		}
		if clean == executableName && item.target.os != "windows" && mode.Perm()&0100 == 0 {
			return fmt.Errorf("unix executable %q has no owner-executable mode bit", clean)
		}
		if size <= 0 || size > maxEntryBytes {
			return fmt.Errorf("required archive entry %q has invalid size %d", clean, size)
		}
		contents, err := io.ReadAll(io.LimitReader(reader, maxEntryBytes+1))
		if err != nil {
			return fmt.Errorf("read required archive entry %q: %w", clean, err)
		}
		if int64(len(contents)) != size {
			return fmt.Errorf("required archive entry %q size changed while reading", clean)
		}
		required[clean] = true
		if clean == executableName {
			if err := validateExecutable(contents, item.target); err != nil {
				return err
			}
			executable = contents
		}
		return nil
	}

	var err error
	if item.target.os == "windows" {
		err = inspectZip(item.path, visit)
	} else {
		err = inspectTarGzip(item.path, visit)
	}
	if err != nil {
		return nil, err
	}
	for name, found := range required {
		if !found {
			return nil, fmt.Errorf("archive is missing %q", name)
		}
	}
	return executable, nil
}

func validateExecutable(data []byte, target target) error {
	invalid := func() error { return fmt.Errorf("executable is not a %s/%s binary", target.os, target.arch) }
	switch target.os {
	case "linux":
		executable, err := elf.NewFile(bytes.NewReader(data))
		if err != nil || executable.Class != elf.ELFCLASS64 || executable.Data != elf.ELFDATA2LSB || executable.Type != elf.ET_EXEC && executable.Type != elf.ET_DYN {
			return invalid()
		}
		expected := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}[target.arch]
		if expected == elf.EM_NONE || executable.Machine != expected {
			return invalid()
		}
	case "darwin":
		executable, err := macho.NewFile(bytes.NewReader(data))
		if err != nil || executable.Type != macho.TypeExec {
			return invalid()
		}
		expected := map[string]macho.Cpu{"amd64": macho.CpuAmd64, "arm64": macho.CpuArm64}[target.arch]
		if expected == 0 || executable.Cpu != expected {
			return invalid()
		}
	case "windows":
		executable, err := pe.NewFile(bytes.NewReader(data))
		if err != nil || executable.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
			return invalid()
		}
		if _, ok := executable.OptionalHeader.(*pe.OptionalHeader64); !ok {
			return invalid()
		}
		expected := map[string]uint16{"amd64": 0x8664, "arm64": 0xaa64}[target.arch]
		if expected == 0 || executable.Machine != expected {
			return invalid()
		}
	default:
		return invalid()
	}
	return nil
}

func cleanArchiveName(name string) (string, error) {
	portable := strings.ReplaceAll(name, `\`, "/")
	clean := path.Clean(portable)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	if name != portable || portable != clean {
		return "", fmt.Errorf("non-canonical archive path %q", name)
	}
	return clean, nil
}

func inspectTarGzip(name string, visit func(string, os.FileMode, int64, io.Reader) error) error {
	data, err := readBoundedRegular(name, maxArchiveBytes)
	if err != nil {
		return err
	}
	compressed := bytes.NewReader(data)
	gzipReader, err := gzip.NewReader(compressed)
	if err != nil {
		return err
	}
	gzipReader.Multistream(false)
	tape := tar.NewReader(gzipReader)
	entries := 0
	for {
		header, err := tape.Next()
		if errors.Is(err, io.EOF) {
			remaining, drainErr := io.Copy(io.Discard, gzipReader)
			closeErr := gzipReader.Close()
			if drainErr != nil {
				return fmt.Errorf("finish gzip stream: %w", drainErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close gzip stream: %w", closeErr)
			}
			if remaining != 0 {
				return errors.New("tar archive contains data after its end marker")
			}
			if compressed.Len() != 0 {
				return errors.New("tar.gz contains trailing compressed data")
			}
			return nil
		}
		if err != nil {
			return err
		}
		entries++
		if entries > maxArchiveEntries {
			return errors.New("archive has too many entries")
		}
		if err := visit(header.Name, header.FileInfo().Mode(), header.Size, tape); err != nil {
			return err
		}
	}
}

func inspectZip(name string, visit func(string, os.FileMode, int64, io.Reader) error) error {
	data, err := readBoundedRegular(name, maxArchiveBytes)
	if err != nil {
		return err
	}
	if !zipEndsAtEOF(data) {
		return errors.New("ZIP archive has a missing or non-terminal end record")
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	if len(reader.File) > maxArchiveEntries {
		return errors.New("archive has too many entries")
	}
	for _, entry := range reader.File {
		if entry.UncompressedSize64 > maxEntryBytes {
			return fmt.Errorf("archive entry %q exceeds size limit", entry.Name)
		}
		contents, err := entry.Open()
		if err != nil {
			return err
		}
		visitErr := visit(entry.Name, entry.Mode(), int64(entry.UncompressedSize64), contents)
		closeErr := contents.Close()
		if visitErr != nil {
			return visitErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func zipEndsAtEOF(data []byte) bool {
	// EOCD is at least 22 bytes and its comment is at most 65535 bytes. Search
	// backward for an EOCD whose declared comment terminates exactly at EOF;
	// zip.NewReader performs the remaining structural validation.
	const (
		eocdSize      = 22
		maxCommentLen = 1<<16 - 1
	)
	start := len(data) - eocdSize
	if start < 0 {
		return false
	}
	minimum := max(0, len(data)-eocdSize-maxCommentLen)
	for offset := start; offset >= minimum; offset-- {
		if data[offset] != 'P' || offset+eocdSize > len(data) || !bytes.Equal(data[offset:offset+4], []byte{'P', 'K', 5, 6}) {
			continue
		}
		commentLength := int(data[offset+20]) | int(data[offset+21])<<8
		if offset+eocdSize+commentLength == len(data) {
			return true
		}
	}
	return false
}

func smokeExecutable(data []byte, version string) error {
	directory, err := os.MkdirTemp("", "relaybox-release-smoke-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	name := filepath.Join(directory, "relaybox")
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.WriteFile(name, data, 0700); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, "version").CombinedOutput()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("version command: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	want := "relaybox " + version
	if got := strings.TrimSpace(string(output)); got != want || strings.HasSuffix(got, " dev") {
		return fmt.Errorf("version output %q, want %q", got, want)
	}
	return nil
}
