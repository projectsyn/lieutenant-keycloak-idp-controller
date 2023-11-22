package controllers

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/google/go-jsonnet"
	lieutenantv1alpha1 "github.com/projectsyn/lieutenant-operator/api/v1alpha1"
	"github.com/wI2L/jsondiff"
	"go.uber.org/multierr"
	"golang.org/x/exp/slices"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/json"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/projectsyn/lieutenant-keycloak-idp-controller/templates"
)

type Clock interface {
	Now() time.Time
}

// ClusterReconciler reconciles a Cluster object
type ClusterReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	KeycloakClient     *gocloak.GoCloak
	KeycloakRealm      string
	KeycloakLoginRealm string
	KeycloakUser       string
	KeycloakPassword   string
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

	gcl := r.KeycloakClient
	token, err := gcl.LoginAdmin(ctx, r.KeycloakUser, r.KeycloakPassword, r.loginRealm())
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to login to keycloak: %w", err)
	}
	defer func() {
		if logoutErr := gcl.LogoutPublicClient(ctx, "admin-cli", r.loginRealm(), token.AccessToken, token.RefreshToken); logoutErr != nil {
			multierr.AppendInto(&err, fmt.Errorf("unable to logout from keycloak: %w", logoutErr))
		}
	}()

	jsonnetCtx := map[string]any{
		"cluster": instance,
	}
	jcr, err := json.Marshal(jsonnetCtx)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to marshal jsonnet context: %w", err)
	}
	jvm := jsonnet.MakeVM()
	jvm.ExtCode("context", string(jcr))

	// Create or updated client
	cRaw, err := jvm.EvaluateAnonymousSnippet("cluster", templates.ClientDefault)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to evaluate jsonnet: %w", err)
	}
	var templatedClient gocloak.Client
	if err := json.Unmarshal([]byte(cRaw), &templatedClient); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to unmarshal jsonnet result: %w", err)
	}
	if templatedClient.ClientID == nil || *templatedClient.ClientID == "" {
		return ctrl.Result{}, fmt.Errorf("`clientId` is empty")
	}
	client, err := r.findClientByClientId(ctx, token.AccessToken, r.KeycloakRealm, *templatedClient.ClientID)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to get client: %w", err)
	}
	if client == nil {
		l.Info("Client not found, creating", "client", templatedClient)
		id, err := gcl.CreateClient(ctx, token.AccessToken, r.KeycloakRealm, templatedClient)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("unable to create client: %w", err)
		}
		l.Info("Client created, requeuing", "id", id)
		return ctrl.Result{Requeue: true}, nil
	}

	l.Info("Client found, updating", "client", client.ID)
	templatedClient.ID = client.ID
	patch, err := jsondiff.Compare(client, templatedClient, jsondiff.Ignores("/secret"))
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to compare existing and templated clients: %w", err)
	}
	if len(patch) == 0 {
		l.Info("No changes to the client detected")
	} else {
		l.Info("Updating client", "changes", patch)
		if err := gcl.UpdateClient(ctx, token.AccessToken, r.KeycloakRealm, templatedClient); err != nil {
			return ctrl.Result{}, fmt.Errorf("unable to update client: %w", err)
		}
	}

	// template client roles
	rolesRaw, err := jvm.EvaluateAnonymousSnippet("client-roles", templates.ClientRolesDefault)
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

	if err := r.createClientRoles(ctx, gcl, token.AccessToken, *client.ID, templatedRoles); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to create client roles: %w", err)
	}

	actualRoles, err := gcl.GetClientRoles(ctx, token.AccessToken, r.KeycloakRealm, *client.ID, gocloak.GetRoleParams{})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to get client roles: %w", err)
	}

	groups := make(map[string][]gocloak.Role)
	for _, role := range templatedRoles {
		if role.Group == "" {
			continue
		}
		ri := slices.IndexFunc(actualRoles, func(r *gocloak.Role) bool {
			return *r.Name == role.Role
		})
		if ri == -1 {
			return ctrl.Result{}, fmt.Errorf("unable to find role %q", role.Role)
		}
		groups[role.Group] = append(groups[role.Group], *actualRoles[ri])
	}
	for groupPath, roles := range groups {
		if len(roles) == 0 {
			l.Info("No roles to map, skipping", "group", groupPath)
			continue
		}

		g, err := gcl.GetGroupByPath(ctx, token.AccessToken, r.KeycloakRealm, groupPath)
		if err != nil {
			var kcErr *gocloak.APIError
			if errors.As(err, &kcErr) && kcErr.Code == http.StatusNotFound {
				l.Info("Group not found, skipping mapping", "group", groupPath)
				continue
			}
			return ctrl.Result{}, fmt.Errorf("unable to get group: %w", err)
		}

		l.Info("Syncing client role group mapping", "group", groupPath, "roles", roles)
		if err := gcl.AddClientRolesToGroup(ctx, token.AccessToken, r.KeycloakRealm, *client.ID, *g.ID, roles); err != nil {
			return ctrl.Result{}, fmt.Errorf("unable to add client roles to group: %w", err)
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&lieutenantv1alpha1.Cluster{}).
		Complete(r)
}

// createClientRoles creates the given client roles if they do not exist yet
func (r *ClusterReconciler) createClientRoles(ctx context.Context, gcl *gocloak.GoCloak, token string, clientId string, roles []roleMapping) error {
	l := log.FromContext(ctx).WithName("ClusterReconciler.createClientRoles")

	var clientRoles []string
	for _, role := range roles {
		clientRoles = append(clientRoles, role.Role)
	}
	slices.Sort(clientRoles)
	clientRoles = slices.Compact(clientRoles)
	for _, role := range clientRoles {
		id, err := gcl.CreateClientRole(ctx, token, r.KeycloakRealm, clientId, gocloak.Role{
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
