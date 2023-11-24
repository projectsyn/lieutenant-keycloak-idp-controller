package controllers

import (
	"context"
	"testing"

	"github.com/Nerzal/gocloak/v13"
	"github.com/go-logr/logr/testr"
	"github.com/projectsyn/lieutenant-keycloak-idp-controller/controllers/mock"
	lieutenantv1alpha1 "github.com/projectsyn/lieutenant-operator/api/v1alpha1"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
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

func Test_ClusterReconciler_Reconcile_CreateClientAndSecret(t *testing.T) {
	ctx := log.IntoContext(context.Background(), testr.New(t))

	mctrl := gomock.NewController(t)
	defer mctrl.Finish()

	mockKeycloak := mock.NewMockPartialKeycloakClient(mctrl)
	mockKeycloak.EXPECT().LoginAdmin(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(&gocloak.JWT{}, nil)
	mockKeycloak.EXPECT().LogoutPublicClient(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	mockVaultAuth := mock.NewMockVaultPartialAuthClient(mctrl)
	mockVaultSecrets := mock.NewMockVaultPartialSecretsClient(mctrl)

	cl := &lieutenantv1alpha1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "test",
			Finalizers: []string{finalizerName},
		},
		Spec: lieutenantv1alpha1.ClusterSpec{
			DisplayName: "test",
		},
	}

	c := fakeClient(t, cl)

	subject := &ClusterReconciler{
		Client: c,
		Scheme: c.Scheme(),

		KeycloakClient:     mockKeycloak,
		VaultAuthClient:    mockVaultAuth,
		VaultSecretsClient: mockVaultSecrets,
	}
	_, err := subject.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cl)})
	require.NoError(t, err)

	require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(cl), cl))
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
