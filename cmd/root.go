package cmd

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cloudbees-io/configure-aws-credentials/internal/auth"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cmd = &cobra.Command{
		Use:          "configure-aws-credentials",
		Short:        "Configures credentials for accessing AWS",
		Long:         "Configures credentials for accessing AWS",
		SilenceUsage: true,
		RunE:         doConfigure,
	}
)

func Execute() error {
	return cmd.Execute()
}

func init() {
	viper.AutomaticEnv()

	viper.SetEnvPrefix("INPUT")

	replacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(replacer)

	inputString("audience", "sts.amazonaws.com", "The audience to use for the OIDC provider")
	inputString("cloudbees-api-token", "", "The CloudBees API Token to use for fetching OIDC ID tokens")
	inputString("cloudbees-api-url", "", "The CloudBees API root URL to use for fetching OIDC ID tokens")
	inputString("aws-access-key-id", "", "AWS Access Key ID")
	inputString("aws-secret-access-key", "", "AWS Secret Access Key")
	inputString("aws-session-token", "", "AWS Session Token")
	inputString("aws-region", "", "AWS Region, e.g. us-east-2")
	inputBool("mask-aws-account-id", true, "Whether to set the AWS account ID for these credentials as a secret value so that it is masked in logs")
	inputString("role-to-assume", "", "Use the provided credentials to assume an IAM role and configure the Actions environment with the assumed role credentials rather than with the provided credentials")
	inputString("web-identity-token-file", "", "Use the web identity token file from the provided file system path in order to assume an IAM role using a web identity")
	inputInt32("role-duration-seconds", -1, "Role duration in seconds (default: 6 hours, 1 hour for OIDC/specified aws-session-token)")
	inputString("role-session-name", "CloudBeesAutomations", "Role session name")
	inputString("role-external-id", "", "The external ID of the role to assume")
	inputBool("role-skip-session-tagging", false, "Skip session tagging during role assumption")
	inputString("http-proxy", "", "Proxy to use for the AWS SDK agent")
	inputBool("role-chaining", false, "Use existing credentials from the environment to assume a new role")
	inputString("inline-session-policy", "", "Inline session policy")
	inputString("managed-session-policies", "", "List of managed session policies")
}

func inputString(name string, value string, usage string) {
	cmd.Flags().String(name, value, usage)
	_ = viper.BindPFlag(name, cmd.Flags().Lookup(name))
}

func inputBool(name string, value bool, usage string) {
	cmd.Flags().Bool(name, value, usage)
	_ = viper.BindPFlag(name, cmd.Flags().Lookup(name))
}

func inputInt32(name string, value int32, usage string) {
	cmd.Flags().Int32(name, value, usage)
	_ = viper.BindPFlag(name, cmd.Flags().Lookup(name))
}

func cliContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		cancel() // exit gracefully
		<-c
		os.Exit(1) // exit immediately on 2nd signal
	}()
	return ctx
}

func doConfigure(command *cobra.Command, args []string) error {
	ctx := cliContext()

	var cfg auth.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return err
	}

	return cfg.Authenticate(ctx)
}
