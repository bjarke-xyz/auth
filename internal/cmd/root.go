package cmd

import (
	"context"
	"net/http"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func Execute(ctx context.Context) int {
	_ = godotenv.Load()

	profile := false
	rootCmd := &cobra.Command{
		Use:   "uber-clone",
		Short: "Uber clone",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if !profile {
				return nil
			}

			f, perr := os.Create("cpu.pprof")
			if perr != nil {
				return perr
			}

			_ = pprof.StartCPUProfile(f)
			return nil
		},
		PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
			if !profile {
				return nil
			}

			pprof.StopCPUProfile()

			f, perr := os.Create("mem.pprof")
			if perr != nil {
				return perr
			}
			defer f.Close()

			runtime.GC()
			err := pprof.WriteHeapProfile(f)
			return err
		},
	}

	rootCmd.PersistentFlags().BoolVarP(&profile, "profile", "p", false, "record CPU pprof")

	serverCmd := ServerCmd(ctx)

	rootCmd.AddCommand(serverCmd)

	go func() {
		_ = http.ListenAndServe("localhost:6060", nil)
	}()

	cmd, _, err := rootCmd.Find(os.Args[1:])
	// default cmd if no cmd is given
	if err == nil && cmd.Use == rootCmd.Use && cmd.Flags().Parse(os.Args[1:]) != pflag.ErrHelp {
		args := append([]string{serverCmd.Use}, os.Args[1:]...)
		rootCmd.SetArgs(args)
	}

	if err := rootCmd.Execute(); err != nil {
		return 1
	}

	return 0
}
