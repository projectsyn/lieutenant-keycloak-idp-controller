package controllers

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/Nerzal/gocloak/v13"
	"github.com/go-logr/logr/testr"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	lieutenantv1alpha1 "github.com/projectsyn/lieutenant-operator/api/v1alpha1"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"go.uber.org/multierr"
	"golang.org/x/exp/maps"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/projectsyn/lieutenant-keycloak-idp-controller/controllers/mock"
	"github.com/projectsyn/lieutenant-keycloak-idp-controller/controllers/testtemplates"
)

const (
	vaultAccessToken = "vaultAccessToken"
	vaultToken       = "vaultToken"
	vaultRole        = "lieutenant-keycloak-idp-controller"

	keycloakLoginRealm  = "admin"
	keycloakRealm       = "testrealm"
	keycloakAccessToken = "accessToken"
)

func Test_ClusterReconciler_Reconcile_AddFinalizer(t *testing.T) {
	ctx := log.IntoContext(context.Background(), testr.New(t))

	cl := &lieutenantv1alpha1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "test",
		},
	}

	c := fakeClient(t, cl)

	subject := &ClusterReconciler{
		Client: c,
		Scheme: c.Scheme(),
	}
	_, err := subject.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cl)})
	require.NoError(t, err)

	require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(cl), cl))
	require.Contains(t, cl.Finalizers, finalizerName)
}

func Test_ClusterReconciler_Reconcile_E2E(t *testing.T) {
	ctx := log.IntoContext(context.Background(), testr.New(t))

	mctrl := gomock.NewController(t)
	defer mctrl.Finish()

	mockKeycloak := mock.NewMockPartialKeycloakClient(mctrl)
	mockVaultAuth := mock.NewMockVaultPartialAuthClient(mctrl)
	mockVaultSecrets := mock.NewMockVaultPartialSecretsClient(mctrl)

	mockKeycloakLogin(mockKeycloak, keycloakLoginRealm)
	mockVaultLogin(mockVaultAuth)
	tkco := trackKeycloakObjects(mockKeycloak)
	tks := trackVaultSecretCreation(mockVaultSecrets)

	cluster := &lieutenantv1alpha1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "test",
			Finalizers: []string{finalizerName},
		},
		Spec: lieutenantv1alpha1.ClusterSpec{
			DisplayName: "test",
		},
	}

	c := fakeClient(t, cluster)

	tkco.groups = append(tkco.groups, gocloak.Group{
		ID:   ptr.To("b45ec6e5-edfc-4823-93f0-9f3012a42f64"),
		Path: ptr.To("/LDAP/VSHN openshiftroot"),
	})

	subject := &ClusterReconciler{
		Client: c,
		Scheme: c.Scheme(),

		KeycloakLoginRealm: keycloakLoginRealm,
		KeycloakRealm:      keycloakRealm,

		KeycloakClient: mockKeycloak,

		VaultTokenSource:   vaultTokenSource,
		VaultAuthClient:    mockVaultAuth,
		VaultSecretsClient: mockVaultSecrets,

		ClientTemplate:            testtemplates.Client,
		ClientRoleMappingTemplate: testtemplates.ClientRoles,

		KeycloakClientIgnorePaths: []string{"/attributes/ignored"},
	}

	require.NoError(t,
		reconcileNTimes(ctx, subject, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cluster)}, 5))

	t.Run("CreateClientAndSecret", func(t *testing.T) {
		require.Len(t, tkco.clients, 1, "should have created a client")
		createdClient := tkco.clients[0]
		require.Equal(t, "cluster_test", *createdClient.ClientID, "should have created client with correct name")

		createdClientRoles := tkco.clientRoles[*createdClient.ID]
		rn := make([]string, len(createdClientRoles))
		for i, r := range createdClientRoles {
			rn[i] = *r.Name
		}
		require.ElementsMatch(t,
			[]string{"restricted-access", "openshiftroot", "openshiftrootswissonly"},
			rn,
			"should have created client roles")

		require.Len(t, tkco.clientRolesToGroupsMapping, 1)
		require.ElementsMatch(t,
			[]string{"openshiftroot"},
			tkco.clientRolesToGroupsMapping[clientGroupMappingKey{clientId: *createdClient.ID, groupId: *tkco.groups[0].ID}],
			"should add mapping to referenced group")

		sk := "test/keycloak/oidcClient"
		require.ElementsMatch(t,
			[]string{sk},
			maps.Keys(tks.secrets),
			"should have created a secret")

		require.Equal(t,
			tks.secrets[sk],
			map[string]any{"secret": md5sum(*createdClient.ClientID)},
			"should have created a secret with the secret returned by keycloak")
	})

	t.Run("UpdateClient", func(t *testing.T) {
		createdClient := tkco.clients[0]
		require.Equal(t, map[string]string{"custom": "attribute", "ignored": "attribute"}, *createdClient.Attributes, "should have attributes from template")
		createdClient.Attributes = &map[string]string{"custom": "attribute", "new": "attribute"}
		_, err := subject.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cluster)})
		require.NoError(t, err)

		updatedClient := tkco.clients[0]
		require.Equal(t, map[string]string{"custom": "attribute", "ignored": "attribute"}, *updatedClient.Attributes, "should have attributes from template")

		createdClient.Attributes = &map[string]string{"custom": "attribute", "ignored": "changed"}
		_, err = subject.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cluster)})
		require.NoError(t, err)

		updatedClient = tkco.clients[0]
		require.Equal(t,
			map[string]string{"custom": "attribute", "ignored": "changed"},
			*updatedClient.Attributes,
			"changes to ignored attributes should not trigger a client update")
	})

	t.Run("UpdateSecret", func(t *testing.T) {
		createdClient := tkco.clients[0]
		sk := "test/keycloak/oidcClient"

		require.Equal(t,
			tks.secrets[sk],
			map[string]any{"secret": md5sum(*createdClient.ClientID)},
			"should have created a secret with the secret returned by keycloak")

		tks.secrets[sk]["secret"] = "invalid"

		_, err := subject.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cluster)})
		require.NoError(t, err)

		require.Equal(t,
			tks.secrets[sk],
			map[string]any{"secret": md5sum(*createdClient.ClientID)},
			"should have updated the secret with the secret returned by keycloak")
	})

	t.Run("DeleteClient", func(t *testing.T) {
		require.NoError(t, c.Delete(ctx, cluster))

		require.NoError(t,
			reconcileNTimes(ctx, subject, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cluster)}, 2))

		require.Len(t, tkco.clients, 0, "should have deleted the client")
		require.Len(t, tks.secrets, 0, "should have deleted the secret")

		require.Error(t, c.Get(ctx, client.ObjectKeyFromObject(cluster), cluster), "cluster should be deleted after finalizer was removed")
	})
}

func md5sum(s string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(s)))
}

func mockKeycloakLogin(mockKeycloak *mock.MockPartialKeycloakClient, loginRealm string) {
	at, rt := keycloakAccessToken, "refresh-token"
	mockKeycloak.EXPECT().LoginAdmin(gomock.Any(), gomock.Any(), gomock.Any(), loginRealm).Return(&gocloak.JWT{AccessToken: at, RefreshToken: rt}, nil).AnyTimes()
	mockKeycloak.EXPECT().LogoutPublicClient(gomock.Any(), "admin-cli", loginRealm, at, rt).Return(nil).AnyTimes()
}

func mockVaultLogin(mockVaultAuth *mock.MockVaultPartialAuthClient) {
	mockVaultAuth.EXPECT().KubernetesLogin(gomock.Any(), gomock.Any(), gomock.Any()).Return(&vault.Response[map[string]interface{}]{
		Auth: &vault.ResponseAuth{
			ClientToken: vaultToken,
		},
	}, nil).AnyTimes()
}

type clientGroupMappingKey struct {
	clientId, groupId string
}

type trackedKeycloakObjects struct {
	clients     []*gocloak.Client
	clientRoles map[string][]*gocloak.Role
	groups      []gocloak.Group

	clientRolesToGroupsMapping map[clientGroupMappingKey][]string
}

func trackKeycloakObjects(mockKeycloak *mock.MockPartialKeycloakClient) *trackedKeycloakObjects {
	tracked := &trackedKeycloakObjects{
		clients:     make([]*gocloak.Client, 0),
		clientRoles: make(map[string][]*gocloak.Role),
		groups:      make([]gocloak.Group, 0),

		clientRolesToGroupsMapping: make(map[clientGroupMappingKey][]string),
	}

	findClient := func(clientId string) *gocloak.Client {
		for _, c := range tracked.clients {
			if *c.ClientID == clientId {
				return c
			}
		}
		return nil
	}

	mockKeycloak.EXPECT().GetClients(gomock.Any(), keycloakAccessToken, keycloakRealm, gomock.Any()).DoAndReturn(
		func(_ context.Context, _, _ string, gcp gocloak.GetClientsParams) ([]*gocloak.Client, error) {
			if c := findClient(*gcp.ClientID); c != nil {
				return []*gocloak.Client{c}, nil
			}
			return []*gocloak.Client{}, nil
		}).AnyTimes()

	mockKeycloak.EXPECT().CreateClient(gomock.Any(), keycloakAccessToken, keycloakRealm, gomock.Any()).DoAndReturn(
		func(_ context.Context, _, _ string, client gocloak.Client) (string, error) {
			if findClient(*client.ClientID) != nil {
				return "", &gocloak.APIError{Code: http.StatusConflict, Message: "Client already exists"}
			}

			id := md5sum(*client.ClientID)
			client.ID = &id
			client.Secret = &id
			tracked.clients = append(tracked.clients, &client)
			return id, nil
		}).AnyTimes()

	mockKeycloak.EXPECT().UpdateClient(gomock.Any(), keycloakAccessToken, keycloakRealm, gomock.Any()).DoAndReturn(
		func(_ context.Context, _, _ string, client gocloak.Client) error {
			oc := findClient(*client.ClientID)
			if oc == nil {
				return &gocloak.APIError{Code: http.StatusNotFound, Message: "Client not found"}
			}

			id := md5sum(*client.ClientID)
			client.ID = &id
			client.Secret = &id
			*oc = client
			return nil
		}).AnyTimes()

	mockKeycloak.EXPECT().DeleteClient(gomock.Any(), keycloakAccessToken, keycloakRealm, gomock.Any()).DoAndReturn(
		func(_ context.Context, _, _ string, clientId string) error {
			for i, c := range tracked.clients {
				if *c.ID == clientId {
					tracked.clients = append(tracked.clients[:i], tracked.clients[i+1:]...)
					return nil
				}
			}
			return &gocloak.APIError{Code: http.StatusNotFound, Message: "Client not found"}
		}).AnyTimes()

	mockKeycloak.EXPECT().GetClientRoles(gomock.Any(), keycloakAccessToken, keycloakRealm, gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _, _, id string, _ gocloak.GetRoleParams) ([]*gocloak.Role, error) {
			if cr, ok := tracked.clientRoles[id]; ok {
				return cr, nil
			}
			return []*gocloak.Role{}, nil
		}).AnyTimes()

	mockKeycloak.EXPECT().CreateClientRole(gomock.Any(), keycloakAccessToken, keycloakRealm, gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _, _, clientId string, role gocloak.Role) (string, error) {
			id := md5sum(*role.Name)
			role.ID = &id
			if cr, ok := tracked.clientRoles[clientId]; ok {
				for _, r := range cr {
					if *r.Name == *role.Name {
						return "", &gocloak.APIError{Code: http.StatusConflict, Message: "Role already exists"}
					}
				}
				tracked.clientRoles[clientId] = append(tracked.clientRoles[clientId], &role)
			} else {
				tracked.clientRoles[clientId] = []*gocloak.Role{&role}
			}
			return id, nil
		}).AnyTimes()

	mockKeycloak.EXPECT().GetGroupByPath(gomock.Any(), keycloakAccessToken, keycloakRealm, gomock.Any()).DoAndReturn(
		func(_ context.Context, _, _ string, groupPath string) (*gocloak.Group, error) {
			for _, g := range tracked.groups {
				if *g.Path == groupPath {
					return &g, nil
				}
			}
			return nil, &gocloak.APIError{Code: http.StatusNotFound}
		}).AnyTimes()

	mockKeycloak.EXPECT().AddClientRolesToGroup(gomock.Any(), keycloakAccessToken, keycloakRealm, gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _, _, idOfClient string, groupID string, roles []gocloak.Role) error {
			rs := slices.Clone(tracked.clientRolesToGroupsMapping[clientGroupMappingKey{clientId: idOfClient, groupId: groupID}])

			for _, r := range roles {
				rs = append(rs, *r.Name)
			}

			slices.Sort(rs)
			tracked.clientRolesToGroupsMapping[clientGroupMappingKey{clientId: idOfClient, groupId: groupID}] = slices.Compact(rs)

			return nil
		}).AnyTimes()

	return tracked
}

type trackedSecrets struct {
	secrets map[string]map[string]any
}

func trackVaultSecretCreation(mockVaultSecrets *mock.MockVaultPartialSecretsClient) *trackedSecrets {
	tr := &trackedSecrets{
		secrets: make(map[string]map[string]any),
	}

	mockVaultSecrets.EXPECT().KvV2Read(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, path string, _ ...vault.RequestOption) (*vault.Response[schema.KvV2ReadResponse], error) {
			if s, ok := tr.secrets[path]; ok {
				return &vault.Response[schema.KvV2ReadResponse]{
					Data: schema.KvV2ReadResponse{
						Data: s,
					},
				}, nil
			}
			return nil, &vault.ResponseError{StatusCode: http.StatusNotFound}
		}).AnyTimes()

	mockVaultSecrets.EXPECT().KvV2Write(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, path string, request schema.KvV2WriteRequest, _ ...vault.RequestOption) (*vault.Response[schema.KvV2WriteResponse], error) {
			tr.secrets[path] = request.Data
			return &vault.Response[schema.KvV2WriteResponse]{}, nil
		}).AnyTimes()

	mockVaultSecrets.EXPECT().KvV2Delete(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, path string, _ ...vault.RequestOption) (*vault.Response[map[string]interface{}], error) {
			delete(tr.secrets, path)
			return &vault.Response[map[string]any]{}, nil
		}).AnyTimes()

	return tr
}

func fakeClient(t *testing.T, initObjs ...client.Object) client.WithWatch {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, lieutenantv1alpha1.AddToScheme(scheme))

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(initObjs...).
		WithStatusSubresource(
			&lieutenantv1alpha1.Cluster{},
		).
		Build()

	return cl
}

func vaultTokenSource() (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken: vaultAccessToken,
	}, nil
}

func reconcileNTimes(ctx context.Context, subject reconcile.Reconciler, req reconcile.Request, n int) error {
	errs := make([]error, 0, n)
	for i := 0; i < n; i++ {
		if _, err := subject.Reconcile(ctx, req); err != nil {
			errs = append(errs, fmt.Errorf("reconcile %d: %w", i, err))
		}
	}
	return multierr.Combine(errs...)
}
