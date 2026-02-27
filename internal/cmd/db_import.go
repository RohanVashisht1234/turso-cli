package cmd

import (
	"errors"
	"path/filepath"
	"strings"

	"fmt"
	"os"
	"syscall"

	"github.com/spf13/cobra"
)

func isFileLocked(filename string) (bool, error) {
	f, err := os.Open(filename)
	if err != nil {
		return false, err
	}
	defer f.Close()

	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return true, nil // File is locked
		}
		return false, fmt.Errorf("failed to check lock: %w", err)
	}

	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false, nil
}

func init() {
	dbCmd.AddCommand(importCmd)
	addGroupFlag(importCmd)
	addRemoteEncryptionKeyFlag(importCmd)
	addRemoteEncryptionCipherFlag(importCmd)
}

var importCmd = &cobra.Command{
	Use:               "import [filename]",
	Short:             "Import a SQLite database file to Turso.",
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: noFilesArg,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		if len(args) == 0 {
			return errors.New("filename is required: 'turso db import <filename>'")
		}
		filename := args[0]

		locked, err := isFileLocked(filename)
		if err != nil {
			return fmt.Errorf("could not check file lock: %w", err)
		}
		if locked {
			return errors.New("database file is locked by another process (close any open connections and try again)")
		}

		fromFileFlag = filename
		name := sanitizeDatabaseName(filename)
		return CreateDatabase(name)
	},
}

// Sanitize a SQLite database filename to be used as a cloud database name.
func sanitizeDatabaseName(filename string) string {
	base := filepath.Base(filename)

	extensions := []string{".db", ".sqlite", ".sqlite3", ".sl3", ".s3db", ".db3"}
	for _, ext := range extensions {
		if strings.HasSuffix(strings.ToLower(base), ext) {
			return base[:len(base)-len(ext)]
		}
	}

	return base
}
