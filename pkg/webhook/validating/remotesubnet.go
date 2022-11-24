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

package validating

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/log"

	webhookutils "github.com/alibaba/hybridnet/pkg/webhook/utils"

	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	multiclusterv1 "github.com/alibaba/hybridnet/pkg/apis/multicluster/v1"
	networkingv1 "github.com/alibaba/hybridnet/pkg/apis/networking/v1"
)

var (
	rsLock          = sync.Mutex{}
	remoteSubnetGVK = gvkConverter(multiclusterv1.GroupVersion.WithKind("RemoteSubnet"))
)

func init() {
	createHandlers[remoteSubnetGVK] = RemoteSubnetCreateValidation
	updateHandlers[remoteSubnetGVK] = RemoteSubnetUpdateValidation
	deleteHandlers[remoteSubnetGVK] = RemoteSubnetDeleteValidation
}

func RemoteSubnetCreateValidation(ctx context.Context, req *admission.Request, handler *Handler) admission.Response {
	rsLock.Lock()
	defer rsLock.Unlock()

	logger := log.FromContext(ctx)

	var err error
	var remoteSubnet = &multiclusterv1.RemoteSubnet{}
	if err = handler.Decoder.Decode(*req, remoteSubnet); err != nil {
		return webhookutils.AdmissionErroredWithLog(http.StatusBadRequest, err, logger)
	}

	var localSubnetList = &networkingv1.SubnetList{}
	if err = handler.Client.List(ctx, localSubnetList); err != nil {
		return webhookutils.AdmissionErroredWithLog(http.StatusInternalServerError, err, logger)
	}
	for i := range localSubnetList.Items {
		var localSubnet = &localSubnetList.Items[i]
		if networkingv1.Intersect(&remoteSubnet.Spec.Range, &localSubnet.Spec.Range) {
			return webhookutils.AdmissionDeniedWithLog(fmt.Sprintf("overlay with existing subnet %s", localSubnet.Name), logger)
		}
	}

	var remoteSubnetList = &multiclusterv1.RemoteSubnetList{}
	if err = handler.Client.List(ctx, remoteSubnetList); err != nil {
		return webhookutils.AdmissionErroredWithLog(http.StatusInternalServerError, err, logger)
	}
	for i := range remoteSubnetList.Items {
		var comparedRemoteCluster = &remoteSubnetList.Items[i]
		if networkingv1.Intersect(&remoteSubnet.Spec.Range, &comparedRemoteCluster.Spec.Range) {
			return webhookutils.AdmissionDeniedWithLog(fmt.Sprintf("overlay with existing remote subnet %s", comparedRemoteCluster.Name), logger)
		}
	}

	return admission.Allowed("validation pass")
}

func RemoteSubnetUpdateValidation(ctx context.Context, req *admission.Request, handler *Handler) admission.Response {
	return admission.Allowed("validation pass")
}

func RemoteSubnetDeleteValidation(ctx context.Context, req *admission.Request, handler *Handler) admission.Response {
	return admission.Allowed("validation pass")
}
