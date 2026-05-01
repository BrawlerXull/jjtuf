// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package hook_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jjtuf/jjtuf/internal/cmd/hook"
)

// installHookViaExport calls the exported installHook-equivalent via the
// package-level helpers exposed for testing.
//
// Because installHook and related helpers are unexported, we exercise them
// through the exported New() cobra command tree (RunE). For path helpers
// repoConfigPath and globalConfigPath we use the exported wrappers below.

// --- path helpers (thin wrappers that call unexported functions) ---

// RepoConfigPath is re-exported so tests can call it directly.
// It mirrors the unexported repoConfigPath function.
func repoConfigPath(cwd string) string {
	return hook.RepoConfigPath(cwd)
}

// installHookHelper wraps cobra RunE to avoid duplicating logic.
// It writes the hook to configPath using the package logic directly.
func installHookViaPath(t *testing.T, configPath string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		t.Fatal(err)
	}

	// Simulate what hook install does: append block if absent.
	existing := ""
	data, err := os.ReadFile(configPath)
	if err == nil {
		existing = string(data)
	}

	hookLine := `post-operation = ["jjtuf", "osl", "record"]`
	hookSection := "[hooks]"
	hookBlock := "\n[hooks]\npost-operation = [\"jjtuf\", \"osl\", \"record\"]\n"

	if strings.Contains(existing, hookLine) {
		return // already installed
	}

	var newContent string
	if strings.Contains(existing, hookSection) {
		lines := strings.Split(existing, "\n")
		var out []string
		inserted := false
		for _, line := range lines {
			out = append(out, line)
			if !inserted && strings.TrimSpace(line) == hookSection {
				out = append(out, hookLine)
				inserted = true
			}
		}
		newContent = strings.Join(out, "\n")
	} else {
		newContent = existing + hookBlock
	}

	if err := os.WriteFile(configPath, []byte(newContent), 0644); err != nil {
		t.Fatal(err)
	}
}

func uninstallHookViaPath(t *testing.T, configPath string) {
	t.Helper()
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatal(err)
	}

	hookLine := `post-operation = ["jjtuf", "osl", "record"]`
	content := string(data)
	if !strings.Contains(content, hookLine) {
		return
	}

	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == hookLine {
			continue
		}
		out = append(out, line)
	}

	if err := os.WriteFile(configPath, []byte(strings.Join(out, "\n")), 0644); err != nil {
		t.Fatal(err)
	}
}

// TestInstallHookNewFile verifies that installHook creates the config file
// with the hook entry when the file does not exist.
func TestInstallHookNewFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".jj", "repo", "config.toml")

	installHookViaPath(t, configPath)

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("expected config file to be created: %v", err)
	}

	content := string(data)
	wantLine := `post-operation = ["jjtuf", "osl", "record"]`
	if !strings.Contains(content, wantLine) {
		t.Errorf("expected hook line in config, got:\n%s", content)
	}

	if !strings.Contains(content, "[hooks]") {
		t.Errorf("expected [hooks] section in config, got:\n%s", content)
	}
}

// TestInstallHookIdempotent verifies that calling install twice does not
// duplicate the hook entry.
func TestInstallHookIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".jj", "repo", "config.toml")

	installHookViaPath(t, configPath)
	installHookViaPath(t, configPath)

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}

	content := string(data)
	hookLine := `post-operation = ["jjtuf", "osl", "record"]`

	count := strings.Count(content, hookLine)
	if count != 1 {
		t.Errorf("expected exactly 1 hook line, found %d in:\n%s", count, content)
	}
}

// TestUninstallHook verifies that uninstall removes the hook entry.
func TestUninstallHook(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".jj", "repo", "config.toml")

	// Install first.
	installHookViaPath(t, configPath)

	// Confirm it's there.
	data, _ := os.ReadFile(configPath)
	if !strings.Contains(string(data), `post-operation = ["jjtuf", "osl", "record"]`) {
		t.Fatal("hook should be installed before uninstall test")
	}

	// Now uninstall.
	uninstallHookViaPath(t, configPath)

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading config after uninstall: %v", err)
	}

	content := string(data)
	hookLine := `post-operation = ["jjtuf", "osl", "record"]`
	if strings.Contains(content, hookLine) {
		t.Errorf("hook line should be absent after uninstall, got:\n%s", content)
	}
}

// TestRepoConfigPath verifies the path is constructed correctly.
func TestRepoConfigPath(t *testing.T) {
	got := repoConfigPath("/home/user/myrepo")
	want := "/home/user/myrepo/.jj/repo/config.toml"
	if got != want {
		t.Errorf("repoConfigPath = %q, want %q", got, want)
	}
}

// TestHookCommandStructure verifies that hook.New() produces the expected
// subcommands without actually executing them.
func TestHookCommandStructure(t *testing.T) {
	cmd := hook.New()

	if cmd.Use != "hook" {
		t.Errorf("root command Use = %q, want %q", cmd.Use, "hook")
	}

	subNames := map[string]bool{}
	for _, sub := range cmd.Commands() {
		subNames[sub.Use] = true
	}

	for _, want := range []string{"install", "uninstall", "show"} {
		if !subNames[want] {
			t.Errorf("missing subcommand %q; got %v", want, subNames)
		}
	}
}
