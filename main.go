package main

import (
	"flag"
	"fmt"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/Nerzal/gocloak/v13"
	"github.com/hashicorp/vault-client-go"
	lieutenantv1alpha1 "github.com/projectsyn/lieutenant-operator/api/v1alpha1"
	"go.uber.org/multierr"
	"golang.org/x/oauth2"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/transport"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/projectsyn/lieutenant-keycloak-idp-controller/controllers"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")

	vaultAddress, vaultToken, vaultTokenFile    string
	vaultRole, vaultLoginMountPath, vaultKvPath string

	keycloakBaseUrl                   string
	keycloakRealm, keycloakLoginRealm string
	keycloakUser, keycloakPassword    string
	enableLegacyWildFlySupport        bool

	clientTemplateFile, clientRoleMappingTemplateFile string
	jsonnetImportPaths                                stringSliceFlag

	keycloakClientIgnorePaths stringSliceFlag
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(lieutenantv1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&keycloakBaseUrl, "keycloak-base-url", "", "The base URL of the Keycloak instance")
	flag.StringVar(&keycloakRealm, "keycloak-realm", "", "The Keycloak realm to use")
	flag.StringVar(&keycloakLoginRealm, "keycloak-login-realm", "", "The Keycloak realm to use for login. If not set, the realm will be used")
	flag.StringVar(&keycloakUser, "keycloak-user", "", "The Keycloak user to use")
	flag.StringVar(&keycloakPassword, "keycloak-password", "", "The Keycloak password to use")
	flag.BoolVar(&enableLegacyWildFlySupport, "keycloak-legacy-wildfly-support", false, "Enable legacy WildFly support for Keycloak")

	flag.StringVar(&vaultAddress, "vault-address", "", "The address of the Vault instance")
	flag.StringVar(&vaultToken, "vault-token", "", "The Vault token to use. Takes precedence over vault-token-file.")
	flag.StringVar(&vaultTokenFile, "vault-token-file", "", "The file containing the Vault token to use. Usually `/var/run/secrets/kubernetes.io/serviceaccount/token`")
	flag.StringVar(&vaultRole, "vault-role", "lieutenant-keycloak-idp-controller", "The Vault role to use.")
	flag.StringVar(&vaultLoginMountPath, "vault-login-mount-path", "lieutenant", "The Vault mount path to use for login.")
	flag.StringVar(&vaultKvPath, "vault-kv-path", "clusters/kv", "The Vault KV path to use.")

	flag.StringVar(&clientTemplateFile, "client-template-file", "templates/client.jsonnet", "The file containing the client template to use.")
	flag.StringVar(&clientRoleMappingTemplateFile, "client-role-mapping-template-file", "templates/client-roles.jsonnet", "The file containing the client role mapping template to use.")
	flag.Var(&jsonnetImportPaths, "jsonnet-import-path", "A list of paths to search for Jsonnet libraries when using `import`. Can be specified multiple times.")

	flag.Var(&keycloakClientIgnorePaths, "keycloak-client-ignore-paths", "A list of JSON Pointer strings (RFC 6901) to ignore when checking if changes to the Keycloak client are relevant. Can be specified multiple times. See https://pkg.go.dev/github.com/wI2L/jsondiff@v0.5.0#Ignores")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	flagErrs := []error{}
	if keycloakBaseUrl == "" {
		flagErrs = append(flagErrs, fmt.Errorf("keycloak-base-url must be set"))
	}
	if keycloakRealm == "" {
		flagErrs = append(flagErrs, fmt.Errorf("keycloak-realm must be set"))
	}
	if keycloakUser == "" {
		flagErrs = append(flagErrs, fmt.Errorf("keycloak-user must be set"))
	}
	if keycloakPassword == "" {
		flagErrs = append(flagErrs, fmt.Errorf("keycloak-password must be set"))
	}
	if flagErr := multierr.Combine(flagErrs...); flagErr != nil {
		setupLog.Error(flagErr, "options are missing")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: server.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "8839d9ec.appuio.io",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	vaultClient, err := vault.New(
		vault.WithAddress(vaultAddress),
	)
	if err != nil {
		setupLog.Error(err, "unable to create vault client")
		os.Exit(1)
	}

	var vtSource func() (*oauth2.Token, error)
	if vaultToken == "" && vaultTokenFile != "" {
		vtSource = transport.NewCachedFileTokenSource(vaultTokenFile).Token
	} else if vaultToken != "" {
		vtSource = func() (*oauth2.Token, error) {
			return &oauth2.Token{
				AccessToken: vaultToken,
			}, nil
		}
	} else {
		setupLog.Error(err, "vault-token or vault-token-file must be set")
		os.Exit(1)
	}

	if _, err := os.ReadFile(clientTemplateFile); err != nil {
		setupLog.Error(err, "unable to read client template file")
		os.Exit(1)
	}
	if _, err := os.ReadFile(clientRoleMappingTemplateFile); err != nil {
		setupLog.Error(err, "unable to read client role mapping template file")
		os.Exit(1)
	}

	var gcOpts []func(*gocloak.GoCloak)
	if enableLegacyWildFlySupport {
		gcOpts = append(gcOpts, gocloak.SetLegacyWildFlySupport())
	}
	if err = (&controllers.ClusterReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),

		VaultAuthClient:     &vaultClient.Auth,
		VaultSecretsClient:  &vaultClient.Secrets,
		VaultTokenSource:    vtSource,
		VaultRole:           vaultRole,
		VaultLoginMountPath: vaultLoginMountPath,
		VaultKvPath:         vaultKvPath,

		KeycloakClient:     gocloak.NewClient(keycloakBaseUrl, gcOpts...),
		KeycloakRealm:      keycloakRealm,
		KeycloakLoginRealm: keycloakLoginRealm,
		KeycloakUser:       keycloakUser,
		KeycloakPassword:   keycloakPassword,

		ClientTemplateFile:            clientTemplateFile,
		ClientRoleMappingTemplateFile: clientRoleMappingTemplateFile,
		JsonnetImportPaths:            jsonnetImportPaths,

		KeycloakClientIgnorePaths: keycloakClientIgnorePaths,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Cluster")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

type stringSliceFlag []string

func (f stringSliceFlag) String() string {
	return fmt.Sprint([]string(f))
}

func (f *stringSliceFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}
