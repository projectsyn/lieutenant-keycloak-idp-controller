package controllers

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/google/go-jsonnet"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	lieutenantv1alpha1 "github.com/projectsyn/lieutenant-operator/api/v1alpha1"
	"github.com/wI2L/jsondiff"
	"go.uber.org/multierr"
	"golang.org/x/oauth2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const finalizerName = "syn.tools/lieutenant-keycloak-idp-controller"

type Clock interface {
	Now() time.Time
}

// ClusterReconciler reconciles a Cluster object
type ClusterReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	VaultTokenSource    func() (*oauth2.Token, error)
	VaultAuthClient     VaultPartialAuthClient
	VaultSecretsClient  VaultPartialSecretsClient
	VaultRole           string
	VaultLoginMountPath string
	VaultKvPath         string

	KeycloakClient     PartialKeycloakClient
	KeycloakRealm      string
	KeycloakLoginRealm string
	KeycloakUser       string
	KeycloakPassword   string

	ClientTemplateFile            string
	ClientRoleMappingTemplateFile string
	JsonnetImportPaths            []string

	KeycloakClientIgnorePaths []string
}

//+kubebuilder:rbac:groups=syn.tools,resources=clusters,verbs=get;list;watch
//+kubebuilder:rbac:groups=syn.tools,resources=clusters/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=syn.tools,resources=clusters/finalizers,verbs=update

// Reconcile reconciles the Cluster resource.
func (r *ClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (res ctrl.Result, err error) {
	l := log.FromContext(ctx).WithName("ClusterReconciler.Reconcile")

	instance := &lieutenantv1alpha1.Cluster{}
	if err := r.Get(ctx, req.NamespacedName, instance); err != nil {
		if apierrors.IsNotFound(err) {
			l.Info("Cluster resource not found. Ignoring since object must be deleted.")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("unable to get Cluster resource: %w", err)
	}
	if instance.DeletionTimestamp != nil {
		if controllerutil.ContainsFinalizer(instance, finalizerName) {
			if err := r.cleanupClient(ctx, instance); err != nil {
				return ctrl.Result{}, fmt.Errorf("unable to cleanup client: %w", err)
			}
			controllerutil.RemoveFinalizer(instance, finalizerName)
			return ctrl.Result{}, r.Update(ctx, instance)
		}
		return ctrl.Result{}, nil
	}
	if updated := controllerutil.AddFinalizer(instance, finalizerName); updated {
		return ctrl.Result{Requeue: true}, r.Update(ctx, instance)
	}

	token, err := r.keycloakLogin(ctx)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to login to keycloak: %w", err)
	}
	defer func() {
		if logoutErr := r.keycloakLogout(ctx, token); logoutErr != nil {
			multierr.AppendInto(&err, fmt.Errorf("unable to logout from keycloak: %w", logoutErr))
		}
	}()

	jvm, err := r.jsonnetVMWithContext(instance)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to create jsonnet vm: %w", err)
	}

	// Create or updated client
	templatedClient, err := r.templateKeycloakClient(jvm)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to template keycloak client: %w", err)
	}

	client, err := r.findClientByClientId(ctx, token.AccessToken, r.KeycloakRealm, *templatedClient.ClientID)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to get client: %w", err)
	}
	if client == nil {
		l.Info("Client not found, creating", "client", templatedClient)
		id, err := r.KeycloakClient.CreateClient(ctx, token.AccessToken, r.KeycloakRealm, templatedClient)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("unable to create client: %w", err)
		}
		l.Info("Client created, requeuing", "id", id)
		return ctrl.Result{Requeue: true}, nil
	}

	l.Info("Client found, updating", "client", client.ID)
	templatedClient.ID = client.ID

	ignores := append([]string{"/secret"}, r.KeycloakClientIgnorePaths...)
	patch, err := jsondiff.Compare(client, templatedClient, jsondiff.Ignores(ignores...))
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to compare existing and templated clients: %w", err)
	}
	if len(patch) == 0 {
		l.Info("No changes to the client detected")
	} else {
		l.Info("Updating client", "changes", patch)
		if err := r.KeycloakClient.UpdateClient(ctx, token.AccessToken, r.KeycloakRealm, templatedClient); err != nil {
			return ctrl.Result{}, fmt.Errorf("unable to update client: %w", err)
		}
	}

	client, err = r.findClientByClientId(ctx, token.AccessToken, r.KeycloakRealm, *templatedClient.ClientID)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to get client after creation or updating: %w", err)
	}
	if client == nil {
		return ctrl.Result{}, fmt.Errorf("client %q not found after creation or updating", *templatedClient.ClientID)
	}

	// Vault secret
	if client.Secret == nil || *client.Secret == "" {
		return ctrl.Result{}, fmt.Errorf("client %q has no secret", *templatedClient.ClientID)
	}
	if err := r.syncVaultSecret(ctx, instance, *client.Secret); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to sync vault secret: %w", err)
	}

	// template client roles
	rolesRaw, err := jvm.EvaluateFile(r.ClientRoleMappingTemplateFile)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to evaluate client-roles jsonnet: %w", err)
	}
	var templatedRoles []roleMapping
	if err := json.Unmarshal([]byte(rolesRaw), &templatedRoles); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to unmarshal client-roles jsonnet result: %w", err)
	}
	slices.SortFunc(templatedRoles, func(a, b roleMapping) int {
		return strings.Compare(a.Role, b.Role)*10 + strings.Compare(a.Group, b.Group)
	})
	templatedRoles = slices.Compact(templatedRoles)

	if err := r.syncClientRoles(ctx, token.AccessToken, *client.ID, templatedRoles); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to sync client roles: %w", err)
	}

	if err := r.syncClientRoleGroupMappings(ctx, token.AccessToken, *client.ID, templatedRoles); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to sync client role group mappings: %w", err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&lieutenantv1alpha1.Cluster{}).
		Complete(r)
}

func (r *ClusterReconciler) cleanupClient(ctx context.Context, instance *lieutenantv1alpha1.Cluster) (err error) {
	l := log.FromContext(ctx).WithName("ClusterReconciler.cleanup")

	jvm, err := r.jsonnetVMWithContext(instance)
	if err != nil {
		return fmt.Errorf("unable to create jsonnet vm: %w", err)
	}

	// call into jsonnet to get the templated client id
	templatedClient, err := r.templateKeycloakClient(jvm)
	if err != nil {
		return fmt.Errorf("unable to template keycloak client: %w", err)
	}

	token, err := r.keycloakLogin(ctx)
	if err != nil {
		return fmt.Errorf("unable to login to keycloak: %w", err)
	}
	defer func() {
		if logoutErr := r.keycloakLogout(ctx, token); logoutErr != nil {
			multierr.AppendInto(&err, fmt.Errorf("unable to logout from keycloak: %w", logoutErr))
		}
	}()

	client, err := r.findClientByClientId(ctx, token.AccessToken, r.KeycloakRealm, *templatedClient.ClientID)
	if err != nil {
		return fmt.Errorf("unable to get client: %w", err)
	}
	if client == nil {
		l.Info("Client not found, skipping cleanup")
		return nil
	}
	l.Info("Client found, deleting", "client", client.ID)
	if err := r.KeycloakClient.DeleteClient(ctx, token.AccessToken, r.KeycloakRealm, *client.ID); err != nil {
		return fmt.Errorf("unable to delete client: %w", err)
	}

	// delete vault secret
	tokenAuth, err := r.vaultRequestToken(ctx)
	if err != nil {
		return fmt.Errorf("unable to login to vault: %w", err)
	}
	secretPath := vaultSecretPath(instance)
	mountPath := vault.WithMountPath(r.VaultKvPath)
	if _, err := r.VaultSecretsClient.KvV2Delete(ctx, secretPath, mountPath, tokenAuth); err != nil {
		return fmt.Errorf("unable to delete vault secret: %w", err)
	}

	return nil
}

// syncClientRoles creates the given client roles if they do not exist yet
// and deletes all roles that are not in the given list.
func (r *ClusterReconciler) syncClientRoles(ctx context.Context, token string, clientId string, roles []roleMapping) error {
	l := log.FromContext(ctx).WithName("ClusterReconciler.syncClientRoles")

	var clientRoles []string
	for _, role := range roles {
		clientRoles = append(clientRoles, role.Role)
	}
	slices.Sort(clientRoles)
	clientRoles = slices.Compact(clientRoles)
	for _, role := range clientRoles {
		role := role
		id, err := r.KeycloakClient.CreateClientRole(ctx, token, r.KeycloakRealm, clientId, gocloak.Role{
			Name: &role,
		})
		if err != nil {
			var kcErr *gocloak.APIError
			if errors.As(err, &kcErr) && kcErr.Code == http.StatusConflict {
				l.Info("Client role already exists", "role", role)
				continue
			}
			l.Error(err, "unable to create client role", "role", role)
			return fmt.Errorf("keycloak error: %w", err)
		}
		l.Info("Client role created", "role", role, "id", id)
	}

	actualRoles, err := r.KeycloakClient.GetClientRoles(ctx, token, r.KeycloakRealm, clientId, gocloak.GetRoleParams{
		Max: ptr.To(-1),
	})
	if err != nil {
		return fmt.Errorf("unable to get client roles: %w", err)
	}

	for _, role := range actualRoles {
		role := role
		if slices.Contains(clientRoles, *role.Name) {
			continue
		}
		l.Info("Deleting client role", "role", *role.Name, "id", *role.ID)
		if err := r.KeycloakClient.DeleteClientRole(ctx, token, r.KeycloakRealm, clientId, *role.Name); err != nil {
			return fmt.Errorf("unable to delete client role: %w", err)
		}
	}

	return nil
}

// syncClientRoleGroupMappings creates the given client role group mappings if they do not exist yet
// and deletes all mappings that are not in the given list.
func (r *ClusterReconciler) syncClientRoleGroupMappings(ctx context.Context, token string, clientId string, roles []roleMapping) error {
	l := log.FromContext(ctx).WithName("ClusterReconciler.syncClientRoleGroupMappings")

	actualRoles, err := r.KeycloakClient.GetClientRoles(ctx, token, r.KeycloakRealm, clientId, gocloak.GetRoleParams{
		Max: ptr.To(-1),
	})
	if err != nil {
		return fmt.Errorf("unable to get client roles: %w", err)
	}

	groups := make(map[string][]gocloak.Role)
	for _, role := range roles {
		if role.Group == "" {
			continue
		}
		ri := slices.IndexFunc(actualRoles, func(r *gocloak.Role) bool {
			return *r.Name == role.Role
		})
		if ri == -1 {
			return fmt.Errorf("unable to find role %q", role.Role)
		}
		groups[role.Group] = append(groups[role.Group], *actualRoles[ri])
	}
	for groupPath, roles := range groups {
		if len(roles) == 0 {
			l.Info("No roles to map, skipping", "group", groupPath)
			continue
		}

		g, err := r.KeycloakClient.GetGroupByPath(ctx, token, r.KeycloakRealm, groupPath)
		if err != nil {
			var kcErr *gocloak.APIError
			if errors.As(err, &kcErr) && kcErr.Code == http.StatusNotFound {
				l.Info("Group not found, skipping mapping", "group", groupPath)
				continue
			}
			return fmt.Errorf("unable to get group: %w", err)
		}

		l.Info("Syncing client role group mapping", "group", groupPath, "roles", roles)
		if err := r.KeycloakClient.AddClientRolesToGroup(ctx, token, r.KeycloakRealm, clientId, *g.ID, roles); err != nil {
			return fmt.Errorf("unable to add client roles to group: %w", err)
		}
	}

	l.Info("Looking for client role group mappings to delete")

	for _, role := range actualRoles {
		groups, err := r.KeycloakClient.GetGroupsByClientRole(ctx, token, r.KeycloakRealm, *role.Name, clientId)
		if err != nil {
			return fmt.Errorf("unable to get groups by client role: %w", err)
		}
		for _, group := range groups {
			if slices.ContainsFunc(roles, func(r roleMapping) bool { return r.Group == *group.Path }) {
				continue
			}
			l.Info("Deleting client role group mapping", "role", *role.Name, "group", *group.Path)
			if err := r.KeycloakClient.DeleteClientRoleFromGroup(ctx, token, r.KeycloakRealm, clientId, *group.ID, []gocloak.Role{*role}); err != nil {
				return fmt.Errorf("unable to delete client role: %w", err)
			}
		}
	}

	return nil
}

// findClientByClientId returns the client with the given client id or nil if no client was found
func (r *ClusterReconciler) findClientByClientId(ctx context.Context, token string, realm string, clientId string) (*gocloak.Client, error) {
	clients, err := r.KeycloakClient.GetClients(
		ctx,
		token,
		realm,
		gocloak.GetClientsParams{
			ClientID: &clientId,
			Max:      ptr.To(-1),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to get clients: %w", err)
	}
	// Since we are filtering by client id, which is unique, there should only be one client
	for _, client := range clients {
		return client, nil
	}

	return nil, nil
}

func (r *ClusterReconciler) jsonnetVMWithContext(instance *lieutenantv1alpha1.Cluster) (*jsonnet.VM, error) {
	jcr, err := json.Marshal(map[string]any{
		"cluster": instance,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to marshal jsonnet context: %w", err)
	}
	jvm := jsonnet.MakeVM()
	jvm.ExtCode("context", string(jcr))
	jvm.Importer(&jsonnet.FileImporter{
		JPaths: r.JsonnetImportPaths,
	})
	return jvm, nil
}

func (r *ClusterReconciler) templateKeycloakClient(jvm *jsonnet.VM) (gocloak.Client, error) {
	cRaw, err := jvm.EvaluateFile(r.ClientTemplateFile)
	if err != nil {
		return gocloak.Client{}, fmt.Errorf("unable to evaluate jsonnet: %w", err)
	}
	var c gocloak.Client
	if err := json.Unmarshal([]byte(cRaw), &c); err != nil {
		return c, fmt.Errorf("unable to unmarshal `cluster` jsonnet result: %w", err)
	}
	if c.ClientID == nil || *c.ClientID == "" {
		return c, fmt.Errorf("invalid cluster template: `clientId` is empty")
	}
	return c, nil
}

func (r *ClusterReconciler) vaultRequestToken(ctx context.Context) (vault.RequestOption, error) {
	vt, err := r.VaultTokenSource()
	if err != nil {
		return nil, fmt.Errorf("unable to get vault token: %w", err)
	}
	tres, err := r.VaultAuthClient.KubernetesLogin(
		ctx,
		schema.KubernetesLoginRequest{Jwt: vt.AccessToken, Role: r.VaultRole},
		vault.WithMountPath(r.VaultLoginMountPath),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to login to vault: %w", err)
	}
	return vault.WithToken(tres.Auth.ClientToken), nil
}

func vaultSecretPath(instance *lieutenantv1alpha1.Cluster) string {
	return path.Join(instance.Spec.TenantRef.Name, instance.Name, "keycloak", "oidcClient")
}

func (r *ClusterReconciler) syncVaultSecret(ctx context.Context, instance *lieutenantv1alpha1.Cluster, secret string) error {
	l := log.FromContext(ctx).WithName("ClusterReconciler.syncVaultSecret")

	tokenAuth, err := r.vaultRequestToken(ctx)
	if err != nil {
		return fmt.Errorf("unable to login to vault: %w", err)
	}
	secretPath := vaultSecretPath(instance)
	mountPath := vault.WithMountPath(r.VaultKvPath)

	var existingSecret string
	res, err := r.VaultSecretsClient.KvV2Read(ctx, secretPath, mountPath, tokenAuth)
	if err != nil && !vault.IsErrorStatus(err, http.StatusNotFound) {
		return fmt.Errorf("unable to read vault secret: %w", err)
	}
	if res != nil && res.Data.Data != nil {
		existingSecret, _ = res.Data.Data["secret"].(string)
	}
	if existingSecret == "" {
		l.Info("No vault secret found")
	}
	if existingSecret == secret {
		l.Info("Vault secret is up to date")
		return nil
	}

	l.Info("Updating vault secret")
	_, err = r.VaultSecretsClient.KvV2Write(
		ctx,
		secretPath,
		schema.KvV2WriteRequest{
			Data: map[string]any{
				"secret": secret,
			},
		},
		mountPath,
		tokenAuth,
	)
	if err != nil {
		return fmt.Errorf("unable to write vault secret: %w", err)
	}

	return nil
}

func (r *ClusterReconciler) keycloakLogin(ctx context.Context) (*gocloak.JWT, error) {
	return r.KeycloakClient.LoginAdmin(ctx, r.KeycloakUser, r.KeycloakPassword, r.loginRealm())
}

func (r *ClusterReconciler) keycloakLogout(ctx context.Context, token *gocloak.JWT) error {
	return r.KeycloakClient.LogoutPublicClient(ctx, "admin-cli", r.loginRealm(), token.AccessToken, token.RefreshToken)
}

func (r *ClusterReconciler) loginRealm() string {
	if r.KeycloakLoginRealm != "" {
		return r.KeycloakLoginRealm
	}
	return r.KeycloakRealm
}

type roleMapping struct {
	Role  string `json:"role"`
	Group string `json:"group"`
}
