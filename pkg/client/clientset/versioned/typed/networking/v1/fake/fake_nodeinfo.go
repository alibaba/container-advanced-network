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
// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	networkingv1 "github.com/alibaba/hybridnet/pkg/apis/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeNodeInfos implements NodeInfoInterface
type FakeNodeInfos struct {
	Fake *FakeNetworkingV1
}

var nodeinfosResource = schema.GroupVersionResource{Group: "networking", Version: "v1", Resource: "nodeinfos"}

var nodeinfosKind = schema.GroupVersionKind{Group: "networking", Version: "v1", Kind: "NodeInfo"}

// Get takes name of the nodeInfo, and returns the corresponding nodeInfo object, and an error if there is any.
func (c *FakeNodeInfos) Get(ctx context.Context, name string, options v1.GetOptions) (result *networkingv1.NodeInfo, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(nodeinfosResource, name), &networkingv1.NodeInfo{})
	if obj == nil {
		return nil, err
	}
	return obj.(*networkingv1.NodeInfo), err
}

// List takes label and field selectors, and returns the list of NodeInfos that match those selectors.
func (c *FakeNodeInfos) List(ctx context.Context, opts v1.ListOptions) (result *networkingv1.NodeInfoList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(nodeinfosResource, nodeinfosKind, opts), &networkingv1.NodeInfoList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &networkingv1.NodeInfoList{ListMeta: obj.(*networkingv1.NodeInfoList).ListMeta}
	for _, item := range obj.(*networkingv1.NodeInfoList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested nodeInfos.
func (c *FakeNodeInfos) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(nodeinfosResource, opts))
}

// Create takes the representation of a nodeInfo and creates it.  Returns the server's representation of the nodeInfo, and an error, if there is any.
func (c *FakeNodeInfos) Create(ctx context.Context, nodeInfo *networkingv1.NodeInfo, opts v1.CreateOptions) (result *networkingv1.NodeInfo, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(nodeinfosResource, nodeInfo), &networkingv1.NodeInfo{})
	if obj == nil {
		return nil, err
	}
	return obj.(*networkingv1.NodeInfo), err
}

// Update takes the representation of a nodeInfo and updates it. Returns the server's representation of the nodeInfo, and an error, if there is any.
func (c *FakeNodeInfos) Update(ctx context.Context, nodeInfo *networkingv1.NodeInfo, opts v1.UpdateOptions) (result *networkingv1.NodeInfo, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(nodeinfosResource, nodeInfo), &networkingv1.NodeInfo{})
	if obj == nil {
		return nil, err
	}
	return obj.(*networkingv1.NodeInfo), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeNodeInfos) UpdateStatus(ctx context.Context, nodeInfo *networkingv1.NodeInfo, opts v1.UpdateOptions) (*networkingv1.NodeInfo, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(nodeinfosResource, "status", nodeInfo), &networkingv1.NodeInfo{})
	if obj == nil {
		return nil, err
	}
	return obj.(*networkingv1.NodeInfo), err
}

// Delete takes name of the nodeInfo and deletes it. Returns an error if one occurs.
func (c *FakeNodeInfos) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(nodeinfosResource, name, opts), &networkingv1.NodeInfo{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeNodeInfos) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(nodeinfosResource, listOpts)

	_, err := c.Fake.Invokes(action, &networkingv1.NodeInfoList{})
	return err
}

// Patch applies the patch and returns the patched nodeInfo.
func (c *FakeNodeInfos) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *networkingv1.NodeInfo, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(nodeinfosResource, name, pt, data, subresources...), &networkingv1.NodeInfo{})
	if obj == nil {
		return nil, err
	}
	return obj.(*networkingv1.NodeInfo), err
}