/*
 Copyright 2021 The Hybridnet Authors.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

package networking

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	networkingv1 "github.com/alibaba/hybridnet/apis/networking/v1"
	"github.com/alibaba/hybridnet/controllers/utils"
	"github.com/alibaba/hybridnet/pkg/constants"
)

// NodeReconciler reconciles a Node object
type NodeReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=nodes/status,verbs=get;update;patch
//+kubebuilder:rbac:groups="",resources=nodes/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Node object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *NodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrllog.FromContext(ctx)

	var node = &corev1.Node{}
	var err error
	if err = r.Get(ctx, req.NamespacedName, node); err != nil {
		log.Error(err, "unable to fetch Node")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	var underlayAttached, overlayAttached bool
	if underlayAttached, overlayAttached, err = utils.DetectNetworkAttachmentOfNode(r, node); err != nil {
		log.Error(err, "unable to detect network attachment")
		return ctrl.Result{}, err
	}

	nodePatch := client.MergeFrom(node.DeepCopy())

	attachedToString := func(attached bool) string {
		if attached {
			return constants.Attached
		}
		return constants.Unattached
	}

	node.Labels[constants.LabelUnderlayNetworkAttachment] = attachedToString(underlayAttached)
	node.Labels[constants.LabelOverlayNetworkAttachment] = attachedToString(overlayAttached)

	if err = r.Patch(ctx, node, nodePatch); err != nil {
		log.Error(err, "unable to patch Node")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}, builder.WithPredicates(
			&utils.IgnoreDeletePredicate{},
			&predicate.ResourceVersionChangedPredicate{},
			&predicate.LabelChangedPredicate{},
			&predicate.Funcs{
				UpdateFunc: func(event event.UpdateEvent) bool {
					oldNetwork, err := utils.FindUnderlayNetworkForNode(r, event.ObjectOld.GetLabels())
					if err != nil {
						// TODO: log here
						return true
					}
					newNetwork, err := utils.FindUnderlayNetworkForNode(r, event.ObjectNew.GetLabels())
					if err != nil {
						// TODO: log here
						return true
					}

					return newNetwork != oldNetwork
				},
			})).
		Watches(&source.Kind{Type: &networkingv1.Network{}}, handler.EnqueueRequestsFromMapFunc(
			// enqueue all nodes here
			func(_ client.Object) []reconcile.Request {
				return utils.ListNodesToReconcileRequests(r)
			},
		), builder.WithPredicates(
			&predicate.GenerationChangedPredicate{},
			&utils.NetworkSpecChangePredicate{},
		)).
		Complete(r)
}