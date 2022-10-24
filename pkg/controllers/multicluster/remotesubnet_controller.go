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

package multicluster

import (
	"context"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	multiclusterv1 "github.com/alibaba/hybridnet/pkg/apis/multicluster/v1"
	networkingv1 "github.com/alibaba/hybridnet/pkg/apis/networking/v1"
	"github.com/alibaba/hybridnet/pkg/constants"
	"github.com/alibaba/hybridnet/pkg/controllers/utils/sets"
)

const ControllerRemoteSubnet = "RemoteSubnet"

// RemoteSubnetReconciler reconciles a RemoteSubnet object
type RemoteSubnetReconciler struct {
	client.Client

	ClusterName         string
	ParentCluster       cluster.Cluster
	ParentClusterObject *multiclusterv1.RemoteCluster

	SubnetSet sets.CallbackSet
}

func (r *RemoteSubnetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := ctrllog.FromContext(ctx).WithValues("Cluster", r.ClusterName)

	defer func() {
		if err != nil {
			log.Error(err, "reconciliation fails")
		}
	}()

	var subnet = &networkingv1.Subnet{}
	if err = r.Get(ctx, req.NamespacedName, subnet); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, wrapError("unable to clean remote subnet", r.cleanRemoteSubnet(ctx, req.Name))
		}
		return ctrl.Result{}, wrapError("unable to get subnet", err)
	}

	if !subnet.DeletionTimestamp.IsZero() {
		log.V(1).Info("ignore terminating subnet")
		_ = r.cleanRemoteSubnet(ctx, req.Name)
		return ctrl.Result{}, nil
	}

	var network = &networkingv1.Network{}
	if err = r.Get(ctx, types.NamespacedName{Name: subnet.Spec.Network}, network); err != nil {
		return ctrl.Result{}, wrapError("unable to get network", err)
	}

	var operationResult controllerutil.OperationResult
	var remoteSubnet = &multiclusterv1.RemoteSubnet{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateRemoteSubnetName(r.ClusterName, req.Name),
		},
	}
	if operationResult, err = controllerutil.CreateOrPatch(ctx, r.ParentCluster.GetClient(), remoteSubnet, func() error {
		if !remoteSubnet.DeletionTimestamp.IsZero() {
			return fmt.Errorf("remote subnet %s is terminating, can not be updated", remoteSubnet.Name)
		}

		if !metav1.IsControlledBy(remoteSubnet, r.ParentClusterObject) {
			if err = controllerutil.SetOwnerReference(r.ParentClusterObject, remoteSubnet, r.ParentCluster.GetScheme()); err != nil {
				return wrapError("unable to set owner reference", err)
			}
		}

		if remoteSubnet.Labels == nil {
			remoteSubnet.Labels = make(map[string]string)
		}
		remoteSubnet.Labels[constants.LabelCluster] = r.ClusterName
		remoteSubnet.Labels[constants.LabelSubnet] = subnet.Name

		remoteSubnet.Spec.Type = network.Spec.Type
		remoteSubnet.Spec.Range = *subnet.Spec.Range.DeepCopy()
		remoteSubnet.Spec.ClusterName = r.ClusterName

		return nil
	}); err != nil {
		return ctrl.Result{}, wrapError("unable to update remote subnet", err)
	}

	r.SubnetSet.Insert(req.Name)

	if operationResult == controllerutil.OperationResultNone {
		log.V(1).Info("remote subnet is up-to-date", "RemoteSubnet", remoteSubnet.Name)
		return ctrl.Result{}, nil
	}

	remoteSubnetPatch := client.MergeFrom(remoteSubnet.DeepCopy())
	remoteSubnet.Status.LastModifyTime = metav1.Now()
	if err = r.ParentCluster.GetClient().Status().Patch(ctx, remoteSubnet, remoteSubnetPatch); err != nil {
		// this error is not fatal, print it and go on
		log.Error(err, "unable to update remote subnet status")
	}

	log.Info("update remote subnet successfully", "RemoteSubnetSpec", remoteSubnet.Spec)
	return ctrl.Result{}, nil
}

func (r *RemoteSubnetReconciler) cleanRemoteSubnet(ctx context.Context, subnetName string) error {
	r.SubnetSet.Delete(subnetName)
	return client.IgnoreNotFound(r.ParentCluster.GetClient().Delete(ctx, &multiclusterv1.RemoteSubnet{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateRemoteSubnetName(r.ClusterName, subnetName),
		},
	}))
}

// SetupWithManager sets up the controller with the Manager.
func (r *RemoteSubnetReconciler) SetupWithManager(mgr ctrl.Manager) (err error) {
	gc := NewRemoteSubnetGarbageCollection(mgr.GetLogger().WithName("cron").WithName("RemoteSubnetGC"), r)
	if err = mgr.Add(gc); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named(ControllerRemoteSubnet).
		For(&networkingv1.Subnet{},
			builder.WithPredicates(
				&predicate.GenerationChangedPredicate{},
			),
		).
		Watches(&source.Channel{Source: gc.EventChannel(), DestBufferSize: 100},
			&handler.EnqueueRequestForObject{},
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
			RecoverPanic:            true,
		}).
		Complete(r)
}

func generateRemoteSubnetName(clusterName, subnetName string) string {
	return fmt.Sprintf("%s.%s", clusterName, subnetName)
}

func splitSubnetNameFromRemoteSubnetName(remoteSubnetName string) string {
	return remoteSubnetName[strings.Index(remoteSubnetName, ".")+1:]
}
