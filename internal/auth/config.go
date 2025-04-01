package auth

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/cloudbees-io/configure-aws-credentials/internal/core"
)

const (
	MAX_AUTOMATION_RUNTIME               = 6 * 3600
	SESSION_ROLE_DURATION                = 3600
	DEFAULT_ROLE_DURATION_FOR_OIDC_ROLES = 3600
	USER_AGENT                           = "configure-aws-credentials-for-cloudbees-automations"
	MAX_TAG_VALUE_LENGTH                 = 256
	SANITIZATION_CHARACTER               = "_"
	ROLE_SESSION_NAME                    = "CloudBeesAutomations"
	REGION_REGEX                         = `^[a-z0-9-]+$`
)

var regionRegex = regexp.MustCompile(REGION_REGEX)

//go:embed config.tmpl
var configFileTemplate string

//go:embed credentials.tmpl
var credentialsFileTemplate string

// Config holds the authentication request configuration
type Config struct {
	// Audience The audience to use for the OIDC provider
	Audience string
	// CloudBeesApiToken The API token to use to request an OIDC ID token with
	CloudBeesApiToken string `mapstructure:"cloudbees-api-token"`
	// CloudBeesApiURL The API endpoint request an OIDC ID token from
	CloudBeesApiURL string `mapstructure:"cloudbees-api-url"`
	// AccessKeyID AWS Access Key ID
	AccessKeyID string `mapstructure:"aws-access-key-id"`
	// SecretAccessKey AWS Secret Access Key
	SecretAccessKey string `mapstructure:"aws-secret-access-key"`
	// SessionToken AWS Session Token
	SessionToken string `mapstructure:"aws-session-token"`
	// Region AWS Region, e.g. us-east-2
	Region string `mapstructure:"aws-region"`
	// MaskAwsAccountID Whether to set the AWS account ID for these credentials as a secret value so that it is masked in logs
	MaskAwsAccountID bool `mapstructure:"mask-aws-account-id"`
	// RoleToAssume Use the provided credentials to assume an IAM role and configure the Actions environment with the assumed role credentials rather than with the provided credentials
	RoleToAssume string `mapstructure:"role-to-assume"`
	// WebIdentityTokenFile Use the web identity token file from the provided file system path in order to assume an IAM role using a web identity
	WebIdentityTokenFile string `mapstructure:"web-identity-token-file"`
	// RoleDurationSeconds Role duration in seconds (default: 6 hours, 1 hour for OIDC/specified aws-session-token)
	RoleDurationSeconds int32 `mapstructure:"role-duration-seconds"`
	// RoleSessionName Role session name
	RoleSessionName string `mapstructure:"role-session-name"`
	// RoleExternalID The external ID of the role to assume
	RoleExternalID string `mapstructure:"role-external-id"`
	// RoleSkipSessionTagging Skip session tagging during role assumption
	RoleSkipSessionTagging bool `mapstructure:"role-skip-session-tagging"`
	// HttpProxy Proxy to use for the AWS SDK agent
	HttpProxy string `mapstructure:"http-proxy"`
	// RoleChaining Use existing credentials from the environment to assume a new role
	RoleChaining bool `mapstructure:"role-chaining"`
	// InlineSessionPolicy Inline session policy
	InlineSessionPolicy string `mapstructure:"inline-session-policy"`
	// ManagedSessionPolicies List of managed session policies
	ManagedSessionPolicies string `mapstructure:"managed-session-policies"`
}

// Authenticates against AWS
func (c *Config) Authenticate(ctx context.Context) error {
	if c.RoleDurationSeconds <= 0 {
		if c.useCloudBeesOIDCProvider() {
			c.RoleDurationSeconds = DEFAULT_ROLE_DURATION_FOR_OIDC_ROLES
		} else if c.SessionToken != "" {
			c.RoleDurationSeconds = SESSION_ROLE_DURATION
		} else if c.RoleChaining {
			c.RoleDurationSeconds = SESSION_ROLE_DURATION
		} else {
			c.RoleDurationSeconds = MAX_AUTOMATION_RUNTIME
		}
	}

	core.Debug("role-duration-seconds=%d", c.RoleDurationSeconds)

	if c.RoleSessionName == "" {
		c.RoleSessionName = ROLE_SESSION_NAME
	}

	core.Debug("role-session-name=%s", c.RoleSessionName)
	core.Debug("region=%s", c.Region)

	if !regionRegex.MatchString(c.Region) {
		return fmt.Errorf("region is not valid: %s", c.Region)
	}

	if err := c.exportRegion(); err != nil {
		return err
	}

	if c.AccessKeyID != "" {
		core.Debug("aws-access-key-id=*****")

		if c.SecretAccessKey == "" {
			core.Debug("aws-secret-access-key=")
			return fmt.Errorf("'aws-secret-access-key' must be provided if 'aws-access-key-id' is provided")
		}

		core.Debug("aws-secret-access-key=*****")
	} else {
		core.Debug("aws-access-key-id=")
	}

	// AWS SDK does not seem to provde a way to create a config with no defaults at all

	if err := os.Unsetenv("AWS_REGION"); err != nil {
		return err
	}
	if err := os.Unsetenv("AWS_DEFAULT_REGION"); err != nil {
		return err
	}

	opts := [](func(*config.LoadOptions) error){
		config.WithRegion(c.Region),
		config.WithDefaultRegion(c.Region),
	}

	core.Debug("role-chaining=%v", c.RoleChaining)

	if !c.RoleChaining {
		opts = append(opts, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, c.SessionToken)))
	} else {
		homePath := os.Getenv("HOME")
		awsPath := filepath.Join(homePath, ".aws")
		opts = append(
			opts,
			config.WithSharedConfigFiles([]string{filepath.Join(awsPath, "config")}),
			config.WithSharedCredentialsFiles([]string{filepath.Join(awsPath, "credentials")}),
		)
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return err
	}

	client := sts.NewFromConfig(cfg)

	if c.RoleToAssume != "" {
		if !strings.HasPrefix(c.RoleToAssume, "arn:aws") {
			// Supports only 'aws' partition. Customers in other partitions ('aws-cn') will need to provide full ARN
			req := &sts.GetCallerIdentityInput{}
			if rsp, err := client.GetCallerIdentity(ctx, req); err != nil {
				return err
			} else {
				c.RoleToAssume = fmt.Sprintf("arn:aws:iam::%s:role/%s", *rsp.Account, c.RoleToAssume)
			}
		}
		core.Debug("role-to-assume=%v", c.RoleToAssume)

		req := &sts.AssumeRoleInput{
			RoleArn:         &c.RoleToAssume,
			RoleSessionName: &c.RoleSessionName,
			DurationSeconds: &c.RoleDurationSeconds,
		}

		core.Debug("role-external-id=%v", c.RoleExternalID)

		if c.RoleExternalID != "" {
			req.ExternalId = &c.RoleExternalID
		}

		core.Debug("inline-session-policy=%v", c.InlineSessionPolicy)

		if c.InlineSessionPolicy != "" {
			req.Policy = &c.InlineSessionPolicy
		}

		core.Debug("managed-session-policies=%v", c.ManagedSessionPolicies)

		if c.ManagedSessionPolicies != "" {
			for _, arn := range strings.Split(c.ManagedSessionPolicies, "\n") {
				req.PolicyArns = append(req.PolicyArns, types.PolicyDescriptorType{Arn: &arn})
			}
		}

		if c.AccessKeyID == "" && !c.RoleChaining {
			params := sts.AssumeRoleWithWebIdentityInput{
				RoleArn:         req.RoleArn,
				RoleSessionName: req.RoleSessionName,
				DurationSeconds: req.DurationSeconds,
				Policy:          req.Policy,
				PolicyArns:      req.PolicyArns,
			}

			if c.WebIdentityTokenFile == "" {
				if c.CloudBeesApiURL == "" {
					return errors.New("could not fetch OIDC token: cloudbees-api-url not provided")
				}

				// OIDC
				var reqURL string
				if reqURL, err = url.JoinPath(c.CloudBeesApiURL, "/token-exchange/oidc-id-token/audience/", c.Audience); err != nil {
					return err
				}

				client := &http.Client{}

				var apiReq *http.Request
				if apiReq, err = http.NewRequest("POST", reqURL, nil); err != nil {
					return err
				}

				apiReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.CloudBeesApiToken))
				apiReq.Header.Set("Content-Type", "application/json")
				apiReq.Header.Set("Accept", "application/json")

				var res *http.Response
				if res, err = client.Do(apiReq); err != nil {
					return err
				}

				defer func() { _ = res.Body.Close() }()

				var bodyBytes []byte
				if bodyBytes, err = io.ReadAll(res.Body); err != nil {
					return err
				}

				if res.StatusCode != 200 {
					return fmt.Errorf("could not fetch OIDC token: \nPOST %s\nHTTP/%d %s\n%s", reqURL, res.StatusCode, res.Status, string(bodyBytes))
				}

				var body struct {
					IdToken string `json:"idToken"`
				}

				if err = json.Unmarshal(bodyBytes, &body); err != nil {
					return err
				}

				if body.IdToken == "" {
					debug := make(map[string]interface{})
					_ = json.Unmarshal(bodyBytes, &debug)
					var keys []string
					for k := range debug {
						keys = append(keys, k)
					}
					return fmt.Errorf("response did not include expected key `idToken`, response keys: %s", strings.Join(keys, ", "))
				}

				params.WebIdentityToken = &body.IdToken

				core.Info("ℹ️Assuming role with OIDC...")
			} else {
				if token, err := os.ReadFile(c.WebIdentityTokenFile); err != nil {
					return fmt.Errorf("could not read web identity token file `%s`: %w", c.WebIdentityTokenFile, err)
				} else {
					s := string(token)
					params.WebIdentityToken = &s
				}

				core.Info("ℹ️Assuming role with web identity token file...")
			}

			if rsp, err := client.AssumeRoleWithWebIdentity(ctx, &params); err != nil {
				claims, err2 := extractClaims(*params.WebIdentityToken)

				if err2 == nil {
					return fmt.Errorf("Could not assume role with web identity: %w\nToken claims:\n%s", err,
						strings.ReplaceAll(claims, "\n", "\n  "))
				}

				return fmt.Errorf("Could not assume role with web identity: %w\nToken claims could not be parsed", err)
			} else {
				c.AccessKeyID = *rsp.Credentials.AccessKeyId
				c.SecretAccessKey = *rsp.Credentials.SecretAccessKey
				c.SessionToken = *rsp.Credentials.SessionToken
			}
		} else {
			core.Info("ℹ️Assuming role with user credentials...")

			if rsp, err := client.AssumeRole(ctx, req); err != nil {
				return err
			} else {
				c.AccessKeyID = *rsp.Credentials.AccessKeyId
				c.SecretAccessKey = *rsp.Credentials.SecretAccessKey
				c.SessionToken = *rsp.Credentials.SessionToken
			}
		}

		core.Info("✅Role assumed")
	} else if c.SessionToken == "" {
		core.Debug("role-to-assume=%v", c.RoleToAssume)

		core.Info("ℹ️Requesting session token...")
		req := sts.GetSessionTokenInput{
			DurationSeconds: &c.RoleDurationSeconds,
		}
		if rsp, err := client.GetSessionToken(ctx, &req); err != nil {
			return err
		} else {
			c.AccessKeyID = *rsp.Credentials.AccessKeyId
			c.SecretAccessKey = *rsp.Credentials.SecretAccessKey
			c.SessionToken = *rsp.Credentials.SessionToken

			core.Info("✅Session token refreshed")
		}
	}

	if err := c.exportCredentials(); err != nil {
		return err
	}

	// set the output

	return c.exportAccountId(ctx)
}

func (c *Config) useCloudBeesOIDCProvider() bool {
	return c.RoleToAssume != "" && c.AccessKeyID != "" && c.WebIdentityTokenFile != "" && !c.RoleChaining
}

func (c *Config) exportRegion() error {
	tmpl := template.New("config")
	tmpl, err := tmpl.Parse(configFileTemplate)
	if err != nil {
		return err
	}

	return renderAwsTemplate("config", tmpl, c)
}

func (c *Config) exportCredentials() error {
	tmpl := template.New("credentials")
	tmpl, err := tmpl.Parse(credentialsFileTemplate)
	if err != nil {
		return err
	}

	return renderAwsTemplate("credentials", tmpl, c)
}

func renderAwsTemplate(fileName string, tmpl *template.Template, data any) (retErr error) {
	homePath := os.Getenv("HOME")
	awsPath := filepath.Join(homePath, ".aws")
	if err := os.MkdirAll(awsPath, os.ModePerm); err != nil {
		return err
	}
	configPath := filepath.Join(awsPath, fileName)
	f, err := os.Create(configPath)
	if err != nil {
		return err
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil && retErr == nil {
			retErr = err
		}
	}(f)

	return tmpl.Execute(f, data)
}

func (c *Config) exportAccountId(ctx context.Context) error {
	opts := [](func(*config.LoadOptions) error){
		config.WithRegion(c.Region),
		config.WithDefaultRegion(c.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, c.SessionToken)),
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return err
	}

	client := sts.NewFromConfig(cfg)

	req := &sts.GetCallerIdentityInput{}
	rsp, err := client.GetCallerIdentity(ctx, req)
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(os.Getenv("CLOUDBEES_OUTPUTS"), "aws-account-id"), []byte(*rsp.Account), 0666)
}

// extractClaims extracts and prints claims from a JWT
func extractClaims(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode payload: %v", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to parse claims: %v", err)
	}

	claimsJSON, _ := json.MarshalIndent(claims, "", "  ")

	return string(claimsJSON), nil
}
