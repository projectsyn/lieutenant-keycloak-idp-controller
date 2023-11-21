package controllers

import (
	"context"
	"testing"

	"github.com/go-logr/logr/testr"
	lieutenantv1alpha1 "github.com/projectsyn/lieutenant-operator/api/v1alpha1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func Test_ClusterReconciler_Reconcile(t *testing.T) {
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
