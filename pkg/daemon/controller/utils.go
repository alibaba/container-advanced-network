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

package controller

import (
	"context"
	"fmt"
	"net"

	"github.com/alibaba/hybridnet/pkg/daemon/bgp"
	daemonutils "github.com/alibaba/hybridnet/pkg/daemon/utils"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/controller-runtime/pkg/event"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/gogf/gf/container/gset"
	"github.com/vishvananda/netlink"

	multiclusterv1 "github.com/alibaba/hybridnet/pkg/apis/multicluster/v1"
	networkingv1 "github.com/alibaba/hybridnet/pkg/apis/networking/v1"
	"github.com/alibaba/hybridnet/pkg/constants"
	"github.com/alibaba/hybridnet/pkg/daemon/iptables"
	"github.com/alibaba/hybridnet/pkg/daemon/neigh"
	"github.com/alibaba/hybridnet/pkg/daemon/route"
)

// simpleTriggerSource is a trigger to add a simple event to queue of controller
type simpleTriggerSource struct {
	queue workqueue.RateLimitingInterface
	key   string
}

func (t *simpleTriggerSource) Start(ctx context.Context, handler handler.EventHandler, queue workqueue.RateLimitingInterface,
	prct ...predicate.Predicate) error {
	t.queue = queue
	return nil
}

func (t *simpleTriggerSource) Trigger() {
	t.queue.Add(reconcile.Request{NamespacedName: types.NamespacedName{
		Name: t.key,
	}})
}

// fixedKeyHandler always add the key string into work queue
type fixedKeyHandler struct {
	handler.Funcs
	key string
}

func (h *fixedKeyHandler) Create(e event.CreateEvent, q workqueue.RateLimitingInterface) {
	q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
		Name: h.key,
	}})
}

// Delete implements EventHandler
func (h *fixedKeyHandler) Delete(e event.DeleteEvent, q workqueue.RateLimitingInterface) {
	q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
		Name: h.key,
	}})
}

// Update implements EventHandler
func (h *fixedKeyHandler) Update(e event.UpdateEvent, q workqueue.RateLimitingInterface) {
	q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
		Name: h.key,
	}})
}

func (c *CtrlHub) getRouterManager(ipVersion networkingv1.IPVersion) *route.Manager {
	if ipVersion == networkingv1.IPv6 {
		return c.routeV6Manager
	}
	return c.routeV4Manager
}

func (c *CtrlHub) getNeighManager(ipVersion networkingv1.IPVersion) *neigh.Manager {
	if ipVersion == networkingv1.IPv6 {
		return c.neighV6Manager
	}
	return c.neighV4Manager
}

func (c *CtrlHub) getIPtablesManager(ipVersion networkingv1.IPVersion) *iptables.Manager {
	if ipVersion == networkingv1.IPv6 {
		return c.iptablesV6Manager
	}
	return c.iptablesV4Manager
}

func (c *CtrlHub) getIPInstanceByAddress(address net.IP) (*networkingv1.IPInstance, error) {
	ctx := context.Background()
	ipInstanceList := &networkingv1.IPInstanceList{}
	if err := c.mgr.GetClient().List(ctx, ipInstanceList, client.MatchingFields{InstanceIPIndex: address.String()}); err != nil {
		return nil, fmt.Errorf("get ip instance by ip %v indexer failed: %v", address.String(), err)
	}

	if len(ipInstanceList.Items) > 1 {
		return nil, fmt.Errorf("get more than one ip instance for ip %v", address.String())
	}

	if len(ipInstanceList.Items) == 1 {
		return &ipInstanceList.Items[0], nil
	}

	if len(ipInstanceList.Items) == 0 {
		// not found
		return nil, nil
	}

	return nil, fmt.Errorf("ip instance for address %v not found", address.String())
}

func (c *CtrlHub) getRemoteVtepByEndpointAddress(address net.IP) (*multiclusterv1.RemoteVtep, error) {
	// try to find remote pod ip
	ctx := context.Background()
	remoteVtepList := &multiclusterv1.RemoteVtepList{}
	if err := c.mgr.GetClient().List(ctx, remoteVtepList, client.MatchingFields{EndpointIPIndex: address.String()}); err != nil {
		return nil, fmt.Errorf("get remote vtep by ip %v indexer failed: %v", address.String(), err)
	}

	if len(remoteVtepList.Items) > 1 {
		// pick up valid remoteVtep
		for _, remoteVtep := range remoteVtepList.Items {
			remoteSubnetList := &multiclusterv1.RemoteSubnetList{}
			if err := c.mgr.GetClient().List(ctx, remoteSubnetList,
				client.MatchingLabels{constants.LabelCluster: remoteVtep.Spec.ClusterName}); err != nil {
				return nil, fmt.Errorf("failed to list remoteSubnet %v", err)
			}

			for _, remoteSubnet := range remoteSubnetList.Items {
				_, cidr, _ := net.ParseCIDR(remoteSubnet.Spec.Range.CIDR)

				if !cidr.Contains(address) {
					continue
				}

				if networkingv1.Intersect(&remoteSubnet.Spec.Range, &networkingv1.AddressRange{
					CIDR:  remoteSubnet.Spec.Range.CIDR,
					Start: address.String(),
					End:   address.String(),
				}) {
					return &remoteVtep, nil
				}
			}
		}

		return nil, fmt.Errorf("get more than one remote vtep for ip %v and cannot find valid one", address.String())
	}

	if len(remoteVtepList.Items) == 1 {
		return &remoteVtepList.Items[0], nil
	}

	return nil, nil
}

func initErrorMessageWrapper(prefix string) func(string, ...interface{}) string {
	return func(format string, args ...interface{}) string {
		return prefix + fmt.Sprintf(format, args...)
	}
}

func parseSubnetSpecRangeMeta(addressRange *networkingv1.AddressRange) (cidr *net.IPNet, gateway, start, end net.IP,
	excludeIPs, reservedIPs []net.IP, err error) {

	if addressRange == nil {
		return nil, nil, nil, nil, nil, nil,
			fmt.Errorf("cannot parse a nil range")
	}

	cidr, err = netlink.ParseIPNet(addressRange.CIDR)
	if err != nil {
		return nil, nil, nil, nil, nil, nil,
			fmt.Errorf("failed to parse subnet cidr %v error: %v", addressRange.CIDR, err)
	}

	if addressRange.Gateway != "" {
		gateway = net.ParseIP(addressRange.Gateway)
		if gateway == nil {
			return nil, nil, nil, nil, nil, nil,
				fmt.Errorf("invalid gateway ip %v", addressRange.Gateway)
		}
	}

	if addressRange.Start != "" {
		start = net.ParseIP(addressRange.Start)
		if start == nil {
			return nil, nil, nil, nil, nil, nil,
				fmt.Errorf("invalid start ip %v", addressRange.Start)
		}
	}

	if addressRange.End != "" {
		end = net.ParseIP(addressRange.End)
		if end == nil {
			return nil, nil, nil, nil, nil, nil,
				fmt.Errorf("invalid end ip %v", addressRange.End)
		}
	}

	for _, ipString := range addressRange.ExcludeIPs {
		excludeIP := net.ParseIP(ipString)
		if excludeIP == nil {
			return nil, nil, nil, nil, nil, nil,
				fmt.Errorf("invalid exclude ip %v", ipString)
		}
		excludeIPs = append(excludeIPs, excludeIP)
	}

	for _, ipString := range addressRange.ReservedIPs {
		reservedIP := net.ParseIP(ipString)
		if reservedIP == nil {
			return nil, nil, nil, nil, nil, nil,
				fmt.Errorf("invalid reserved ip %v", ipString)
		}
		reservedIPs = append(reservedIPs, reservedIP)
	}

	return
}

func isIPListEqual(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}

	if len(a) == 0 || len(b) == 0 {
		return false
	}

	return gset.NewStrSetFrom(a).Equal(gset.NewStrSetFrom(b))
}

func nodeBelongsToNetwork(nodeName string, network *networkingv1.Network) bool {
	if networkingv1.GetNetworkType(network) == networkingv1.NetworkTypeOverlay {
		return true
	}
	isUnderlayOnHost := false
	for _, n := range network.Status.NodeList {
		if n == nodeName {
			isUnderlayOnHost = true
			break
		}
	}
	return isUnderlayOnHost
}

func collectGlobalNetworkInfoAndInit(ctx context.Context, client client.Reader, nodeVxlanIfName, nodeName string,
	bgpManager *bgp.Manager, recordBGPPeers bool) (vxlanForwardNodeIfName string, bgpPeerIP net.IP, err error) {

	networkList := &networkingv1.NetworkList{}
	if err = client.List(ctx, networkList); err != nil {
		err = fmt.Errorf("failed to list network: %v", err)
		return
	}

	for _, network := range networkList.Items {
		switch networkingv1.GetNetworkMode(&network) {
		case networkingv1.NetworkModeVxlan:
			netID := network.Spec.NetID
			vxlanForwardNodeIfName, err = daemonutils.GenerateVxlanNetIfName(nodeVxlanIfName, netID)
			if err != nil {
				err = fmt.Errorf("failed to generate vxlan forward node if name: %v", err)
				return
			}
		case networkingv1.NetworkModeBGP:
			// check if this node belongs to the network, ignore it if not
			if !nodeBelongsToNetwork(nodeName, &network) {
				continue
			}

			if network.Spec.NetID == nil {
				err = fmt.Errorf("the net id of network %v must to be set", network.Name)
				return

			}

			localAS := uint32(*network.Spec.NetID)
			if err = bgpManager.TryStart(localAS); err != nil {
				err = fmt.Errorf("try start bgp manager for network %v failed: %v", network.Name, err)
				return
			}

			if recordBGPPeers {
				if len(network.Spec.Config.BGPPeers) != 1 {
					err = fmt.Errorf("no bgp peer or multiple bgp peers are not supported for network %v", network.Name)
					return
				}

				for _, peer := range network.Spec.Config.BGPPeers {
					bgpManager.RecordPeer(peer.Address, peer.Password, int(peer.ASN), peer.GracefulRestartSeconds)
				}
			}

			bgpPeerIP = net.ParseIP(network.Spec.Config.BGPPeers[0].Address)
			if bgpPeerIP == nil {
				err = fmt.Errorf("get invalid bgp peer address %v for network %v",
					network.Spec.Config.BGPPeers[0].Address, network.Name)
				return
			}
		}
	}

	return
}
