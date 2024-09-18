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
	"fmt"
	"net"

	"github.com/alibaba/hybridnet/pkg/constants"
	"github.com/alibaba/hybridnet/pkg/utils"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/gogf/gf/container/gset"
	"github.com/vishvananda/netlink"

	networkingv1 "github.com/alibaba/hybridnet/pkg/apis/networking/v1"
	"github.com/alibaba/hybridnet/pkg/daemon/iptables"
	"github.com/alibaba/hybridnet/pkg/daemon/neigh"
	"github.com/alibaba/hybridnet/pkg/daemon/route"
)

func (c *Controller) getRouterManager(ipVersion networkingv1.IPVersion) *route.Manager {
	if ipVersion == networkingv1.IPv6 {
		return c.routeV6Manager
	}
	return c.routeV4Manager
}

func (c *Controller) getNeighManager(ipVersion networkingv1.IPVersion) *neigh.Manager {
	if ipVersion == networkingv1.IPv6 {
		return c.neighV6Manager
	}
	return c.neighV4Manager
}

func (c *Controller) getIPtablesManager(ipVersion networkingv1.IPVersion) *iptables.Manager {
	if ipVersion == networkingv1.IPv6 {
		return c.iptablesV6Manager
	}
	return c.iptablesV4Manager
}

func (c *Controller) getIPInstanceByAddress(address net.IP) (*networkingv1.IPInstance, error) {
	ipInstanceList, err := c.ipInstanceIndexer.ByIndex(ByInstanceIPIndexer, address.String())
	if err != nil {
		return nil, fmt.Errorf("get ip instance by ip %v indexer failed: %v", address.String(), err)
	}

	if len(ipInstanceList) > 1 {
		return nil, fmt.Errorf("get more than one ip instance for ip %v", address.String())
	}

	if len(ipInstanceList) == 1 {
		instance, ok := ipInstanceList[0].(*networkingv1.IPInstance)
		if !ok {
			return nil, fmt.Errorf("transform obj to ipinstance failed")
		}

		return instance, nil
	}

	if len(ipInstanceList) == 0 {
		// not found
		return nil, nil
	}

	return nil, fmt.Errorf("ip instance for address %v not found", address.String())
}

func (c *Controller) getRemoteVtepByEndpointAddress(address net.IP) (*networkingv1.RemoteVtep, error) {
	// try to find remote pod ip
	remoteVtepList, err := c.remoteVtepIndexer.ByIndex(ByEndpointIPIndexer, address.String())
	if err != nil {
		return nil, fmt.Errorf("get remote vtep by ip %v indexer failed: %v", address.String(), err)
	}

	if len(remoteVtepList) > 1 {
		// pick up valid remoteVtep
		for _, remoteVtep := range remoteVtepList {
			vtep, ok := remoteVtep.(*networkingv1.RemoteVtep)
			if !ok {
				return nil, fmt.Errorf("transform obj to remote vtep failed")
			}

			clusterSelector := labels.SelectorFromSet(labels.Set{
				constants.LabelCluster: vtep.Spec.ClusterName,
			})

			remoteSubnetList, err := c.remoteSubnetLister.List(clusterSelector)
			if err != nil {
				return nil, fmt.Errorf("failed to list remoteSubnet %v", err)
			}

			for _, remoteSubnet := range remoteSubnetList {
				_, cidr, _ := net.ParseCIDR(remoteSubnet.Spec.Range.CIDR)

				if !cidr.Contains(address) {
					continue
				}

				if utils.Intersect(&remoteSubnet.Spec.Range, &networkingv1.AddressRange{
					CIDR:  remoteSubnet.Spec.Range.CIDR,
					Start: address.String(),
					End:   address.String(),
				}) {
					return vtep, nil
				}
			}
		}

		return nil, fmt.Errorf("get more than one remote vtep for ip %v and cannot find valid one", address.String())
	}

	if len(remoteVtepList) == 1 {
		vtep, ok := remoteVtepList[0].(*networkingv1.RemoteVtep)
		if !ok {
			return nil, fmt.Errorf("transform obj to remote vtep failed")
		}

		return vtep, nil
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

	gateway = net.ParseIP(addressRange.Gateway)
	if gateway == nil {
		return nil, nil, nil, nil, nil, nil,
			fmt.Errorf("invalid gateway ip %v", addressRange.Gateway)
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
