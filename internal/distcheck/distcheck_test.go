package distcheck

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var fixtureEntries = map[string][]byte{
	"LICENSE":                []byte("license"),
	"README.md":              []byte("readme"),
	"THIRD_PARTY_NOTICES.md": []byte("notices"),
}

func TestVerifyCompleteDistribution(t *testing.T) {
	directory, _ := writeDistribution(t)
	if err := Verify(directory, "v1.2.3", false); err != nil {
		t.Fatal(err)
	}
}

func TestValidateTag(t *testing.T) {
	for _, tag := range []string{
		"v0.0.0",
		"v1.2.3",
		"v1.2.3-rc.1",
		"v1.2.3-alpha-1",
	} {
		if _, err := ValidateTag(tag); err != nil {
			t.Errorf("valid tag %q: %v", tag, err)
		}
	}
	for _, tag := range []string{
		"1.2.3",
		"v1.2",
		"v01.2.3",
		"v1.02.3",
		"v1.2.03",
		"v1.2.3-",
		"v1.2.3-01",
		"v1.2.3-rc..1",
		"v1.2.3+",
		"v1.2.3+build.20260806",
		"v1.2.3+build+other",
		"v1.2.3+not_allowed",
	} {
		if _, err := ValidateTag(tag); err == nil {
			t.Errorf("invalid tag %q was accepted", tag)
		}
	}
}

func TestVerifyRejectsIncompleteUnexpectedOrMismatchedDistribution(t *testing.T) {
	t.Run("missing archive", func(t *testing.T) {
		directory, names := writeDistribution(t)
		if err := os.Remove(filepath.Join(directory, names[len(names)-1])); err != nil {
			t.Fatal(err)
		}
		if err := Verify(directory, "1.2.3", false); err == nil || !strings.Contains(err.Error(), "missing release archive") {
			t.Fatalf("missing archive error = %v", err)
		}
	})
	t.Run("unexpected archive", func(t *testing.T) {
		directory, _ := writeDistribution(t)
		if err := os.WriteFile(filepath.Join(directory, "relaybox_1.2.3_linux_riscv64.tar.gz"), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := Verify(directory, "1.2.3", false); err == nil || !strings.Contains(err.Error(), "unexpected release archive") {
			t.Fatalf("unexpected archive error = %v", err)
		}
	})
	t.Run("wrong expected version", func(t *testing.T) {
		directory, _ := writeDistribution(t)
		if err := Verify(directory, "v9.9.9", false); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("version error = %v", err)
		}
	})
}

func TestVerifyRejectsChecksumAndArchiveCorruption(t *testing.T) {
	t.Run("checksum mismatch in non-first archive", func(t *testing.T) {
		directory, names := writeDistribution(t)
		file, err := os.OpenFile(filepath.Join(directory, names[1]), os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteString("corrupt"); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if err := Verify(directory, "1.2.3", false); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
			t.Fatalf("corrupt archive error = %v", err)
		}
	})

	t.Run("zip CRC after recomputed manifest", func(t *testing.T) {
		directory, names := writeDistribution(t)
		selected := target{os: "windows", arch: "amd64"}
		name := archiveName("1.2.3", selected)
		archivePath := filepath.Join(directory, name)
		data, err := os.ReadFile(archivePath)
		if err != nil {
			t.Fatal(err)
		}
		index := bytes.Index(data, fixtureEntries["README.md"])
		if index < 0 {
			t.Fatal("stored ZIP fixture data not found")
		}
		data[index] ^= 0xff
		if err := os.WriteFile(archivePath, data, 0600); err != nil {
			t.Fatal(err)
		}
		writeChecksums(t, directory, names)
		if err := Verify(directory, "1.2.3", false); err == nil || !strings.Contains(err.Error(), "checksum") {
			t.Fatalf("ZIP CRC error = %v", err)
		}
	})

	t.Run("tar gzip footer after recomputed manifest", func(t *testing.T) {
		directory, names := writeDistribution(t)
		selected := target{os: "linux", arch: "amd64"}
		archivePath := filepath.Join(directory, archiveName("1.2.3", selected))
		data, err := os.ReadFile(archivePath)
		if err != nil {
			t.Fatal(err)
		}
		data[len(data)-1] ^= 0xff
		if err := os.WriteFile(archivePath, data, 0600); err != nil {
			t.Fatal(err)
		}
		writeChecksums(t, directory, names)
		if err := Verify(directory, "1.2.3", false); err == nil || !strings.Contains(err.Error(), "gzip") {
			t.Fatalf("gzip footer error = %v", err)
		}
	})

	for _, archiveTarget := range []target{{os: "linux", arch: "arm64"}, {os: "windows", arch: "arm64"}} {
		archiveTarget := archiveTarget
		t.Run("trailing data "+archiveTarget.os, func(t *testing.T) {
			directory, names := writeDistribution(t)
			archivePath := filepath.Join(directory, archiveName("1.2.3", archiveTarget))
			file, err := os.OpenFile(archivePath, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteString("polyglot-trailer"); err != nil {
				file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			writeChecksums(t, directory, names)
			if err := Verify(directory, "1.2.3", false); err == nil || !strings.Contains(strings.ToLower(err.Error()), "trailing") && !strings.Contains(err.Error(), "non-terminal") {
				t.Fatalf("trailing %s error = %v", archiveTarget.os, err)
			}
		})
	}
}

func TestVerifyRejectsInvalidArchiveContents(t *testing.T) {
	t.Run("wrong executable target", func(t *testing.T) {
		directory, names := writeDistribution(t)
		selected := target{os: "darwin", arch: "arm64"}
		entries := archiveEntries(selected)
		entries["relaybox"] = fakeExecutable(target{os: "darwin", arch: "amd64"})
		writeArchive(t, filepath.Join(directory, archiveName("1.2.3", selected)), selected, entries)
		writeChecksums(t, directory, names)
		if err := Verify(directory, "1.2.3", false); err == nil || !strings.Contains(err.Error(), "darwin/arm64 binary") {
			t.Fatalf("wrong executable error = %v", err)
		}
	})

	t.Run("missing third-party notice", func(t *testing.T) {
		directory, names := writeDistribution(t)
		selected := target{os: "linux", arch: "arm64"}
		entries := archiveEntries(selected)
		delete(entries, "THIRD_PARTY_NOTICES.md")
		writeArchive(t, filepath.Join(directory, archiveName("1.2.3", selected)), selected, entries)
		writeChecksums(t, directory, names)
		if err := Verify(directory, "1.2.3", false); err == nil || !strings.Contains(err.Error(), "THIRD_PARTY_NOTICES.md") {
			t.Fatalf("missing notice error = %v", err)
		}
	})

	t.Run("unexpected entry", func(t *testing.T) {
		directory, names := writeDistribution(t)
		selected := target{os: "linux", arch: "amd64"}
		entries := archiveEntries(selected)
		entries["unexpected.txt"] = []byte("unexpected")
		writeArchive(t, filepath.Join(directory, archiveName("1.2.3", selected)), selected, entries)
		writeChecksums(t, directory, names)
		if err := Verify(directory, "1.2.3", false); err == nil || !strings.Contains(err.Error(), "unexpected entry") {
			t.Fatalf("unexpected entry error = %v", err)
		}
	})

	t.Run("non-executable Unix binary", func(t *testing.T) {
		directory, names := writeDistribution(t)
		selected := target{os: "linux", arch: "amd64"}
		writeTarGzipWithExecutableMode(t, filepath.Join(directory, archiveName("1.2.3", selected)), archiveEntries(selected), 0644)
		writeChecksums(t, directory, names)
		if err := Verify(directory, "1.2.3", false); err == nil || !strings.Contains(err.Error(), "executable mode") {
			t.Fatalf("non-executable mode error = %v", err)
		}
	})

	t.Run("other-only executable Unix binary", func(t *testing.T) {
		directory, names := writeDistribution(t)
		selected := target{os: "darwin", arch: "amd64"}
		writeTarGzipWithExecutableMode(t, filepath.Join(directory, archiveName("1.2.3", selected)), archiveEntries(selected), 0401)
		writeChecksums(t, directory, names)
		if err := Verify(directory, "1.2.3", false); err == nil || !strings.Contains(err.Error(), "owner-executable mode") {
			t.Fatalf("other-only executable mode error = %v", err)
		}
	})

	t.Run("non-canonical path", func(t *testing.T) {
		directory, names := writeDistribution(t)
		selected := target{os: "linux", arch: "arm64"}
		entries := archiveEntries(selected)
		entries["nested/../LICENSE"] = entries["LICENSE"]
		delete(entries, "LICENSE")
		writeArchive(t, filepath.Join(directory, archiveName("1.2.3", selected)), selected, entries)
		writeChecksums(t, directory, names)
		if err := Verify(directory, "1.2.3", false); err == nil || !strings.Contains(err.Error(), "non-canonical") {
			t.Fatalf("non-canonical path error = %v", err)
		}
	})
}

func TestVerifyRejectsUnsafeOrIncompleteChecksumManifest(t *testing.T) {
	directory, names := writeDistribution(t)
	manifest := filepath.Join(directory, "checksums.txt")
	data, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if err := os.WriteFile(manifest, []byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(directory, "1.2.3", false); err == nil || !strings.Contains(err.Error(), "entries") {
		t.Fatalf("incomplete manifest error = %v", err)
	}

	writeChecksums(t, directory, names)
	data, err = os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	lines = strings.Split(strings.TrimSpace(string(data)), "\n")
	fields := strings.Fields(lines[0])
	lines[0] = fields[0] + "  ../" + fields[1]
	if err := os.WriteFile(manifest, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(directory, "1.2.3", false); err == nil || !strings.Contains(err.Error(), "unsafe name") {
		t.Fatalf("unsafe manifest error = %v", err)
	}
}

func writeDistribution(t *testing.T) (string, []string) {
	t.Helper()
	directory := t.TempDir()
	var names []string
	for _, target := range expectedTargets {
		name := archiveName("1.2.3", target)
		writeArchive(t, filepath.Join(directory, name), target, archiveEntries(target))
		names = append(names, name)
	}
	sort.Strings(names)
	writeChecksums(t, directory, names)
	return directory, names
}

func archiveName(version string, target target) string {
	extension := ".tar.gz"
	if target.os == "windows" {
		extension = ".zip"
	}
	return fmt.Sprintf("relaybox_%s_%s_%s%s", version, target.os, target.arch, extension)
}

func archiveEntries(target target) map[string][]byte {
	entries := make(map[string][]byte, len(fixtureEntries)+1)
	for name, contents := range fixtureEntries {
		entries[name] = append([]byte(nil), contents...)
	}
	executableName := "relaybox"
	if target.os == "windows" {
		executableName += ".exe"
	}
	entries[executableName] = fakeExecutable(target)
	return entries
}

func fakeExecutable(target target) []byte {
	switch target.os {
	case "linux":
		data := make([]byte, 64)
		copy(data, "\x7fELF")
		data[4], data[5], data[6] = 2, 1, 1
		binary.LittleEndian.PutUint16(data[16:18], 2)
		machine := uint16(62)
		if target.arch == "arm64" {
			machine = 183
		}
		binary.LittleEndian.PutUint16(data[18:20], machine)
		binary.LittleEndian.PutUint32(data[20:24], 1)
		binary.LittleEndian.PutUint16(data[52:54], 64)
		return data
	case "darwin":
		data := make([]byte, 32)
		binary.LittleEndian.PutUint32(data[:4], 0xfeedfacf)
		machine := uint32(0x01000007)
		if target.arch == "arm64" {
			machine = 0x0100000c
		}
		binary.LittleEndian.PutUint32(data[4:8], machine)
		binary.LittleEndian.PutUint32(data[12:16], 2)
		return data
	case "windows":
		data := make([]byte, 328)
		copy(data, "MZ")
		binary.LittleEndian.PutUint32(data[0x3c:0x40], 64)
		copy(data[64:68], "PE\x00\x00")
		machine := uint16(0x8664)
		if target.arch == "arm64" {
			machine = 0xaa64
		}
		binary.LittleEndian.PutUint16(data[68:70], machine)
		binary.LittleEndian.PutUint16(data[84:86], 240)
		binary.LittleEndian.PutUint16(data[86:88], 0x0002)
		binary.LittleEndian.PutUint16(data[88:90], 0x020b)
		binary.LittleEndian.PutUint32(data[196:200], 16)
		return data
	default:
		return []byte("invalid")
	}
}

func writeArchive(t *testing.T, name string, target target, entries map[string][]byte) {
	t.Helper()
	if target.os == "windows" {
		writeZip(t, name, entries)
		return
	}
	writeTarGzip(t, name, entries)
}

func writeTarGzip(t *testing.T, name string, entries map[string][]byte) {
	writeTarGzipWithExecutableMode(t, name, entries, 0755)
}

func writeTarGzipWithExecutableMode(t *testing.T, name string, entries map[string][]byte, executableMode int64) {
	t.Helper()
	file, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tape := tar.NewWriter(gzipWriter)
	for _, entryName := range sortedEntryNames(entries) {
		contents := entries[entryName]
		mode := int64(0644)
		if entryName == "relaybox" {
			mode = executableMode
		}
		if err := tape.WriteHeader(&tar.Header{Name: entryName, Mode: mode, Size: int64(len(contents))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tape.Write(contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := tape.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeZip(t *testing.T, name string, entries map[string][]byte) {
	t.Helper()
	file, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	zipWriter := zip.NewWriter(file)
	for _, entryName := range sortedEntryNames(entries) {
		header := &zip.FileHeader{Name: entryName, Method: zip.Store}
		header.SetMode(0644)
		if entryName == "relaybox.exe" {
			header.SetMode(0755)
		}
		entry, err := zipWriter.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(entries[entryName]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeChecksums(t *testing.T, directory string, names []string) {
	t.Helper()
	file, err := os.Create(filepath.Join(directory, "checksums.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		artifact, err := os.Open(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, artifact); err != nil {
			artifact.Close()
			t.Fatal(err)
		}
		if err := artifact.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintf(file, "%x  %s\n", hash.Sum(nil), name); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func sortedEntryNames(entries map[string][]byte) []string {
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
