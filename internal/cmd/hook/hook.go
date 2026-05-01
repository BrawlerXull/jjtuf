// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package hook

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

const (
	hookLine    = `post-operation = ["jjtuf", "osl", "record"]`
	hookSection = "[hooks]"
	hookBlock   = "\n[hooks]\npost-operation = [\"jjtuf\", \"osl\", \"record\"]\n"
)

// New creates the hook command group.
func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Manage the jjtuf post-operation hook for jj",
		Long: `Install, uninstall, or show the jj post-operation hook that
automatically runs 'jjtuf osl record' after every jj operation.`,
	}

	cmd.AddCommand(installCmd())
	cmd.AddCommand(uninstallCmd())
	cmd.AddCommand(showCmd())

	return cmd
}

// repoConfigPath returns the path to the repo-level jj config file.
func repoConfigPath(cwd string) string {
	return filepath.Join(cwd, ".jj", "repo", "config.toml")
}

// RepoConfigPath is the exported variant of repoConfigPath, exposed for tests.
func RepoConfigPath(cwd string) string {
	return repoConfigPath(cwd)
}

// globalConfigPath returns the path to the user-level jj config file.
func globalConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "jj", "config.toml")
}

// installHook writes the post-operation hook entry to the given config file.
// Returns true if the hook was newly installed, false if already present.
func installHook(configPath string) (bool, error) {
	// Read existing content (file may not exist yet).
	existing := ""
	data, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("reading config file: %w", err)
	}
	if err == nil {
		existing = string(data)
	}

	// Already installed?
	if strings.Contains(existing, hookLine) {
		return false, nil
	}

	// Ensure parent directory exists.
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return false, fmt.Errorf("creating config directory: %w", err)
	}

	var newContent string

	if strings.Contains(existing, hookSection) {
		// [hooks] section exists but our key is missing — insert after [hooks].
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
		// No [hooks] section — append the whole block.
		newContent = existing + hookBlock
	}

	if err := os.WriteFile(configPath, []byte(newContent), 0644); err != nil {
		return false, fmt.Errorf("writing config file: %w", err)
	}

	return true, nil
}

// uninstallHook removes the post-operation hook entry from the config file.
// Returns true if the hook was found and removed, false if not present.
func uninstallHook(configPath string) (bool, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("reading config file: %w", err)
	}

	content := string(data)
	if !strings.Contains(content, hookLine) {
		return false, nil
	}

	// Filter out the hook line.
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == hookLine {
			continue
		}
		out = append(out, line)
	}
	newContent := strings.Join(out, "\n")

	if err := os.WriteFile(configPath, []byte(newContent), 0644); err != nil {
		return false, fmt.Errorf("writing config file: %w", err)
	}

	return true, nil
}

// isHookInstalled reports whether the hook is present in the given config file.
func isHookInstalled(configPath string) bool {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), hookLine)
}

func installCmd() *cobra.Command {
	var global bool

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install the jjtuf post-operation hook",
		Long: `Writes a post-operation hook entry to the jj config file so that
'jjtuf osl record' runs automatically after every jj operation.

Without --global: writes to .jj/repo/config.toml (repo-level, shared).
With --global:    writes to ~/.config/jj/config.toml (user-level).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var configPath string
			if global {
				configPath = globalConfigPath()
				if configPath == "" {
					return fmt.Errorf("could not determine home directory")
				}
			} else {
				cwd, err := os.Getwd()
				if err != nil {
					return fmt.Errorf("getting current directory: %w", err)
				}
				configPath = repoConfigPath(cwd)
			}

			installed, err := installHook(configPath)
			if err != nil {
				return err
			}

			if !installed {
				cmd.Println("Hook already installed.")
				return nil
			}

			cmd.Printf("Hook installed in %s\n", configPath)
			cmd.Println("Hook installed. jjtuf osl record will run automatically after each jj operation.")
			return nil
		},
	}

	cmd.Flags().BoolVar(&global, "global", false, "Install into the user-level config (~/.config/jj/config.toml)")
	return cmd
}

func uninstallCmd() *cobra.Command {
	var global bool

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the jjtuf post-operation hook",
		Long: `Removes the post-operation hook entry from the jj config file.

Without --global: modifies .jj/repo/config.toml (repo-level).
With --global:    modifies ~/.config/jj/config.toml (user-level).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var configPath string
			if global {
				configPath = globalConfigPath()
				if configPath == "" {
					return fmt.Errorf("could not determine home directory")
				}
			} else {
				cwd, err := os.Getwd()
				if err != nil {
					return fmt.Errorf("getting current directory: %w", err)
				}
				configPath = repoConfigPath(cwd)
			}

			removed, err := uninstallHook(configPath)
			if err != nil {
				return err
			}

			if !removed {
				cmd.Println("Hook not found (already removed?)")
				return nil
			}

			cmd.Printf("Hook removed from %s\n", configPath)
			return nil
		},
	}

	cmd.Flags().BoolVar(&global, "global", false, "Remove from the user-level config (~/.config/jj/config.toml)")
	return cmd
}

func showCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show hook installation status",
		Long:  `Shows whether the jjtuf post-operation hook is installed (repo and/or global).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("getting current directory: %w", err)
			}

			repoPath := repoConfigPath(cwd)
			globalPath := globalConfigPath()

			repoInstalled := isHookInstalled(repoPath)
			globalInstalled := globalPath != "" && isHookInstalled(globalPath)

			cmd.Println("Hook status:")

			if repoInstalled {
				cmd.Printf("  [repo]   INSTALLED  (%s)\n", repoPath)
				cmd.Printf("           command: %s\n", hookLine)
			} else {
				cmd.Printf("  [repo]   not installed  (%s)\n", repoPath)
			}

			if globalPath != "" {
				if globalInstalled {
					cmd.Printf("  [global] INSTALLED  (%s)\n", globalPath)
					cmd.Printf("           command: %s\n", hookLine)
				} else {
					cmd.Printf("  [global] not installed  (%s)\n", globalPath)
				}
			}

			if !repoInstalled && !globalInstalled {
				cmd.Println()
				cmd.Println("Run 'jjtuf hook install' to enable automatic OSL recording.")
			}

			// Check if jj is in PATH and show its version.
			cmd.Println()
			jjPath, err := exec.LookPath("jj")
			if err != nil {
				cmd.Println("jj: not found in PATH")
			} else {
				cmd.Printf("jj: %s\n", jjPath)
				out, err := exec.Command("jj", "--version").Output()
				if err == nil {
					cmd.Printf("    version: %s", strings.TrimSpace(string(out)))
					cmd.Println()
				}
			}

			return nil
		},
	}
}
