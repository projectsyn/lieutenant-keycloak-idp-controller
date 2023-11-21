package controllers

import (
	"context"
	"fmt"
	"time"

	lieutenantv1alpha1 "github.com/projectsyn/lieutenant-operator/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type Clock interface {
	Now() time.Time
}

// ClusterReconciler reconciles a Cluster object
type ClusterReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=syn.tools,resources=clusters,verbs=get;list;watch
//+kubebuilder:rbac:groups=syn.tools,resources=clusters/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=syn.tools,resources=clusters/finalizers,verbs=update

// Reconcile reconciles the Cluster resource.
func (r *ClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx).WithName("ClusterReconciler.Reconcile")

	instance := &lieutenantv1alpha1.Cluster{}
	err := r.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		if apierrors.IsNotFound(err) {
			l.Info("Cluster resource not found. Ignoring since object must be deleted.")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("unable to get Cluster resource: %w", err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&lieutenantv1alpha1.Cluster{}).
		Complete(r)
}
