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

package clusterchecker

import (
	"context"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	networkingv1 "github.com/alibaba/hybridnet/pkg/apis/networking/v1"
	"github.com/alibaba/hybridnet/pkg/constants"
	clientutils "github.com/alibaba/hybridnet/pkg/controllers/utils"
)

const SubnetCheckName = "SubnetNonCross"

type Subnet struct {
	LocalClient client.Client
}

func (o *Subnet) Check(ctx context.Context, clusterManager ctrl.Manager, opts ...Option) CheckResult {
	options := ToOptions(opts...)

	subnetsOfCluster, err := clientutils.ListSubnets(ctx, clusterManager.GetAPIReader())
	if err != nil {
		return NewResult(err)
	}

	localSubnets, err := clientutils.ListSubnets(ctx, o.LocalClient)
	if err != nil {
		return NewResult(err)
	}
	localRemoteSubnets, err := clientutils.ListRemoteSubnets(ctx, o.LocalClient)
	if err != nil {
		return NewResult(err)
	}

	for i := range subnetsOfCluster.Items {
		var subnetOfCluster = &subnetsOfCluster.Items[i]

		for j := range localSubnets.Items {
			var localSubnet = &localSubnets.Items[j]
			if networkingv1.Intersect(&subnetOfCluster.Spec.Range, &localSubnet.Spec.Range) {
				return NewResult(fmt.Errorf("subnet %s in cluster intersect with local subnet %s", subnetOfCluster.Name, localSubnet.Name))
			}
		}

		for k := range localRemoteSubnets.Items {
			var localRemoteSubnet = &localRemoteSubnets.Items[k]
			var loopback = localRemoteSubnet.Labels[constants.LabelCluster] == options.ClusterName &&
				localRemoteSubnet.Labels[constants.LabelSubnet] == subnetOfCluster.Name
			if !loopback && networkingv1.Intersect(&subnetOfCluster.Spec.Range, &localRemoteSubnet.Spec.Range) {
				return NewResult(fmt.Errorf("subnet %s in cluster intersect with local remote subnet %s", subnetOfCluster.Name, localRemoteSubnet.Name))
			}
		}
	}

	return NewResult(nil)
}
