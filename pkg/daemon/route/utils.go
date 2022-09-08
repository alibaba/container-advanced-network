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

package route

import (
	"fmt"
	"net"

	"github.com/alibaba/hybridnet/pkg/daemon/iptables"

	networkingv1 "github.com/alibaba/hybridnet/pkg/apis/networking/v1"

	"golang.org/x/sys/unix"

	daemonutils "github.com/alibaba/hybridnet/pkg/daemon/utils"

	"github.com/vishvananda/netlink"
)

const (
	MinRouteTableNum = 10000
	MaxRouteTableNum = 40000

	MaxRulePriority   = 32767
	NodeLocalTableNum = 255

	fromRuleMask = iptables.KubeProxyMasqueradeMark + iptables.FuleNATedPodTrafficMark
	fromRuleMark = 0x0
)

type SubnetInfo struct {
	cidr             *net.IPNet
	gateway          net.IP
	excludeIPs       []net.IP
	includedIPRanges []*daemonutils.IPRange

	// the virtual network interface (can be directly physical interface) for container to use
	forwardNodeIfName string

	// if overlay pod outside traffic need to be NATed
	autoNatOutgoing bool

	// if underlay subnet is on this host node
	isUnderlayOnHost bool

	mode networkingv1.NetworkMode
}

type SubnetInfoMap map[string]*SubnetInfo

func checkIfRouteTableEmpty(tableNum, family int) (bool, error) {
	routeList, err := netlink.RouteListFiltered(family, &netlink.Route{
		Table: tableNum,
	}, netlink.RT_FILTER_TABLE)

	if err != nil {
		return false, fmt.Errorf("failed to list route for table %v: %v", tableNum, err)
	}

	if len(routeList) == 0 {
		return true, nil
	}

	return false, nil
}

func listRoutesByTable(tableNum, family int) ([]netlink.Route, error) {
	routeList, err := netlink.RouteListFiltered(family, &netlink.Route{
		Table: tableNum,
	}, netlink.RT_FILTER_TABLE)

	if err != nil {
		return nil, fmt.Errorf("failed to list route for table %v: %v", tableNum, err)
	}

	return routeList, nil
}

// findHighestUnusedRulePriority find out the highest unused rule priority after node local rule
func findHighestUnusedRulePriority(family int) (int, error) {
	ruleList, err := netlink.RuleList(family)
	if err != nil {
		return -1, fmt.Errorf("failed to list rules: %v", err)
	}

	priorityMap := map[int]bool{}
	nodeLocalRulePrio := 0
	for _, rule := range ruleList {
		if rule.Table == NodeLocalTableNum {
			nodeLocalRulePrio = realRulePriority(rule.Priority)
		}
		priorityMap[realRulePriority(rule.Priority)] = true
	}

	for priority := 0; priority <= MaxRulePriority; priority++ {
		if _, inUsed := priorityMap[priority]; !inUsed {
			// priority is not in used and lower than local rule
			if priority > nodeLocalRulePrio {
				return priority, nil
			}
		}
	}

	return -1, fmt.Errorf("cannot find unused rule priority")
}

func appendHighestUnusedPriorityRuleIfNotExist(src *net.IPNet, table, family int, mark, mask int) error {
	exist, _, err := checkIfRuleExist(src, table, family)
	if err != nil {
		return fmt.Errorf("failed to check rule (src: %v, table: %v) exist: %v", src.String(), table, err)
	}

	if exist {
		// rule exist
		return nil
	}

	priority, err := findHighestUnusedRulePriority(family)
	if err != nil {
		return fmt.Errorf("failed to find highest unused rule priority: %v", err)
	}

	rule := netlink.NewRule()
	rule.Src = src
	rule.Table = table
	rule.Priority = priority
	rule.Family = family
	rule.Mask = mask
	rule.Mark = mark

	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("failed to add policy rule %v: %v", rule.String(), err)
	}

	return nil
}

// findEmptyRouteTable found the first empty route table in range MinRouteTableNum ~ MaxRouteTableNum
func findEmptyRouteTable(family int) (int, error) {
	for i := MinRouteTableNum; i < MaxRouteTableNum; i++ {
		empty, err := checkIfRouteTableEmpty(i, family)
		if err != nil {
			return 0, fmt.Errorf("failed to check route table %v empty: %v", i, err)
		}

		if empty {
			return i, nil
		}
	}
	return 0, fmt.Errorf("cannot find empty route table in range %v~%v", MinRouteTableNum, MaxRouteTableNum)
}

func checkIsFromPodSubnetRule(rule netlink.Rule) bool {
	return rule.Src != nil && rule.Mask == fromRuleMask &&
		rule.Table >= MinRouteTableNum && rule.Table <= MaxRouteTableNum
}

func clearRouteTable(table int, family int) error {
	defaultRouteDst := defaultRouteDstByFamily(family)

	routeList, err := netlink.RouteListFiltered(family, &netlink.Route{
		Table: table,
	}, netlink.RT_FILTER_TABLE)

	if err != nil {
		return fmt.Errorf("failed to list route for table %v: %v", table, err)
	}

	for _, r := range routeList {
		if r.Dst == nil {
			r.Dst = defaultRouteDst
		}

		if err = netlink.RouteDel(&r); err != nil {
			return fmt.Errorf("failed to delete route %v for table %v: %v", r.String(), table, err)
		}
	}
	return nil
}

func ensureFromPodSubnetRuleAndRoutes(forwardNodeIfName string, cidr *net.IPNet,
	gateway net.IP, autoNatOutgoing bool, family int, underlaySubnetInfoMap SubnetInfoMap,
	underlayExcludeIPBlockMap map[string]*net.IPNet, mode networkingv1.NetworkMode) error {

	var table int
	var err error

	ruleExist, existRule, err := checkIfRuleExist(cidr, -1, family)
	if err != nil {
		return fmt.Errorf("failed to check rule (src: %v, table: %v) exist: %v", cidr.String(), table, err)
	}

	// Add subnet rule if not exist.
	if !ruleExist {
		table, err = findEmptyRouteTable(family)
		if err != nil {
			return fmt.Errorf("failed to find empty route table: %v", err)
		}
	} else {
		table = existRule.Table
	}

	forwardLink, err := netlink.LinkByName(forwardNodeIfName)
	if err != nil {
		return fmt.Errorf("failed to get forward link %v: %v", forwardNodeIfName, err)
	}

	switch mode {
	case networkingv1.NetworkModeVxlan:
		if err := ensureRoutesForVxlanSubnet(forwardLink, cidr, table, autoNatOutgoing, family,
			underlaySubnetInfoMap, underlayExcludeIPBlockMap); err != nil {
			return fmt.Errorf("failed to ensure routes for vxlan subnet %v: %v", cidr.String(), err)
		}
	case networkingv1.NetworkModeVlan:
		if err := ensureRoutesForVlanSubnet(forwardLink, cidr, gateway, table, family); err != nil {
			return fmt.Errorf("failed to ensure routes for vlan subnet %v: %v", cidr.String(), err)
		}
	case networkingv1.NetworkModeBGP, networkingv1.NetworkModeGlobalBGP:
		if err := ensureRoutesForBGPSubnet(forwardLink, cidr, table, gateway); err != nil {
			return fmt.Errorf("failed to ensure routes for bgp subnet %v: %v", cidr.String(), err)
		}
	default:
		return fmt.Errorf("unsupported network mode %v", mode)
	}

	// Add rule at the last in case error happens while failed to add any routes to table.
	if !ruleExist {
		if err := appendHighestUnusedPriorityRuleIfNotExist(cidr, table, family, fromRuleMark, fromRuleMask); err != nil {
			return fmt.Errorf("failed to append from subnet rule for cidr %v: %v", cidr, err)
		}
	}

	return nil
}

func ensureRoutesForVxlanSubnet(forwardLink netlink.Link, cidr *net.IPNet, table int, autoNatOutgoing bool,
	family int, underlaySubnetInfoMap SubnetInfoMap, underlayExcludeIPBlockMap map[string]*net.IPNet) error {

	routeList, err := netlink.RouteListFiltered(family, &netlink.Route{
		Table: table,
	}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("failed to list route for table %v: %v", table, err)
	}

	if !autoNatOutgoing {
		defaultRoute := &netlink.Route{
			Dst:       defaultRouteDstByFamily(family),
			LinkIndex: forwardLink.Attrs().Index,
			Table:     table,
			Scope:     netlink.SCOPE_UNIVERSE,
		}

		if err := netlink.RouteReplace(defaultRoute); err != nil {
			return fmt.Errorf("failed to add overlay subnet %v default route %v: %v", cidr.String(), defaultRoute.String(), err)
		}

		for _, route := range routeList {
			// Delete extra useless routes.
			if route.Dst != nil {
				if err := netlink.RouteDel(&route); err != nil {
					return fmt.Errorf("failed to delete overlay route %v for table %v: %v", route.String(), table, err)
				}
			}
		}

	} else {
		for _, route := range routeList {
			// skip exclude routes
			if isExcludeRoute(&route) {
				continue
			}

			if route.Dst != nil {
				if _, exist := underlaySubnetInfoMap[route.Dst.String()]; exist {
					continue
				}
			} else {
				route.Dst = defaultRouteDstByFamily(family)
			}

			// Delete extra useless routes.
			if err := netlink.RouteDel(&route); err != nil {
				return fmt.Errorf("failed to delete overlay route %v for table %v: %v", route.String(), table, err)
			}
		}

		for _, subnet := range underlaySubnetInfoMap {
			subnetRoute := &netlink.Route{
				LinkIndex: forwardLink.Attrs().Index,
				Dst:       subnet.cidr,
				Table:     table,
				Scope:     netlink.SCOPE_UNIVERSE,
			}

			if err := netlink.RouteReplace(subnetRoute); err != nil {
				return fmt.Errorf("failed to set overlay route %v for table %v: %v", subnetRoute.String(), table, err)
			}
		}

		// For overlay pod to access underlay excluded ip addresses, should not be forced to pass through vxlan device.
		if err := ensureExcludedIPBlockRoutes(underlayExcludeIPBlockMap, table, family); err != nil {
			return fmt.Errorf("failed to ensure exclude all ip block routes: %v", err)
		}
	}
	return nil
}

func ensureRoutesForVlanSubnet(forwardLink netlink.Link, cidr *net.IPNet, gateway net.IP, table, family int) error {
	localAddrList, err := netlink.AddrList(nil, family)
	if err != nil {
		return fmt.Errorf("failed to list local addresses: %v", err)
	}

	if !cidr.Contains(gateway) {
		return fmt.Errorf("vlan gateway address %v is not inside the vlan subnet cidr %v", gateway, cidr)
	}

	isLocalSubnet := false
	for _, address := range localAddrList {
		if cidr.Contains(address.IP) {
			// Check if address is an enhanced address or used to connect a subnet.
			if address.Flags&unix.IFA_F_NOPREFIXROUTE == 0 {
				isLocalSubnet = true
				break
			}
		}
	}

	subnetDirectRoute := &netlink.Route{
		LinkIndex: forwardLink.Attrs().Index,
		Dst:       cidr,
		Table:     table,
		// cannot add default route if the scope of subnet direct route is not "link"
		Scope: netlink.SCOPE_LINK,
	}

	if isLocalSubnet {
		// Check if forward interface has default route which has the same gateway ip with this hybridnet subnet.
		defaultRoute, err := daemonutils.GetDefaultRoute(family)
		if err != nil && err != daemonutils.NotExist {
			return fmt.Errorf("failed to get default route: %v", err)
		}

		if defaultRoute != nil {
			if defaultRoute.LinkIndex == forwardLink.Attrs().Index &&
				defaultRoute.Gw != nil && !defaultRoute.Gw.Equal(gateway) {
				return fmt.Errorf("exist default route of forward interface %v has a different gateway %v with %v",
					forwardLink.Attrs().Name, defaultRoute.Gw, gateway)
			}
		}

		// Check if forward interface has subnet direct route.
		directRouteList, err := netlink.RouteListFiltered(family, &netlink.Route{
			LinkIndex: forwardLink.Attrs().Index,
			Dst:       cidr,
		}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_DST)

		if err != nil {
			return fmt.Errorf("failed to list direct route for interface %v and subnet %v: %v",
				forwardLink.Attrs().Name, cidr.String(), err)
		}

		if len(directRouteList) == 0 {
			return fmt.Errorf("forward interface %v should have direct route for local subnet %v",
				forwardLink.Attrs().Name, cidr.String())
		}

		subnetDirectRoute.Src = directRouteList[0].Src
	}

	// avoid to use onlink flag because it doesn't work for ipv6 routes until linux 4.16
	defaultRoute := &netlink.Route{
		LinkIndex: forwardLink.Attrs().Index,
		Table:     table,
		Scope:     netlink.SCOPE_UNIVERSE,
		Gw:        gateway,
	}

	if err := netlink.RouteReplace(subnetDirectRoute); err != nil {
		return fmt.Errorf("failed to add vlan subent %v direct route %v: %v", cidr.String(), subnetDirectRoute.String(), err)
	}

	if err := netlink.RouteReplace(defaultRoute); err != nil {
		return fmt.Errorf("failed to add vlan subnet %v default route %v: %v", cidr.String(), defaultRoute.String(), err)
	}

	return nil
}

func ensureRoutesForBGPSubnet(forwardLink netlink.Link, cidr *net.IPNet, table int, gateway net.IP) error {
	// don't use onlink flag in case the gateway is not a reachable next hop
	defaultRoute := &netlink.Route{
		LinkIndex: forwardLink.Attrs().Index,
		Table:     table,
		Scope:     netlink.SCOPE_UNIVERSE,
		Gw:        gateway,
	}

	if err := netlink.RouteReplace(defaultRoute); err != nil {
		return fmt.Errorf("failed to add bgp subnet %v default route %v: %v", cidr.String(), defaultRoute.String(), err)
	}

	return nil
}

func realRulePriority(priority int) int {
	if priority == -1 {
		return 0
	}
	return priority
}

func checkIfRuleExist(src *net.IPNet, table, family int) (bool, *netlink.Rule, error) {
	ruleList, err := netlink.RuleList(family)
	if err != nil {
		return false, nil, fmt.Errorf("list subnet policy rules error: %v", err)
	}

	for _, rule := range ruleList {
		if src == rule.Src || (src != nil && rule.Src != nil && src.String() == rule.Src.String()) {
			if table > 0 {
				if rule.Table == table {
					// rule exist
					return true, &rule, nil
				}
			} else {
				// rule exist
				return true, &rule, nil
			}
		}
	}

	return false, nil, nil
}

func defaultRouteDstByFamily(family int) *net.IPNet {
	if family == netlink.FAMILY_V6 {
		return &net.IPNet{
			IP:   net.ParseIP("::").To16(),
			Mask: net.CIDRMask(0, 128),
		}
	}

	return &net.IPNet{
		IP:   net.ParseIP("0.0.0.0").To4(),
		Mask: net.CIDRMask(0, 32),
	}
}

func ensureExcludedIPBlockRoutes(excludeIPBlockMap map[string]*net.IPNet, table, family int) error {
	excludedRouteList, err := netlink.RouteListFiltered(family, &netlink.Route{
		Table: table,
		Type:  unix.RTN_THROW,
	}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_TYPE)

	if err != nil {
		return fmt.Errorf("failed to list excluded routes: %v", err)
	}

	for _, route := range excludedRouteList {
		if _, exists := excludeIPBlockMap[route.Dst.String()]; !exists {
			if err := netlink.RouteDel(&route); err != nil {
				return fmt.Errorf("failed delete excluded route %v: %v", route, err)
			}
		}
	}

	for _, cidr := range excludeIPBlockMap {
		if err := netlink.RouteReplace(&netlink.Route{
			Dst:   cidr,
			Table: table,
			Type:  unix.RTN_THROW,
		}); err != nil {
			return fmt.Errorf("failed to add excluded route for block %v: %v", cidr.String(), err)
		}
	}

	return nil
}

func findExcludeIPBlockMap(subnetInfoMap SubnetInfoMap) (map[string]*net.IPNet, error) {
	excludeIPBlockMap := map[string]*net.IPNet{}
	for _, info := range subnetInfoMap {
		excludeIPBlocks, err := daemonutils.FindSubnetExcludeIPBlocks(info.cidr, info.includedIPRanges,
			info.gateway, info.excludeIPs)

		if err != nil {
			return nil, fmt.Errorf("failed to find excluded ip blocks for subnet %v: %v", info.cidr, err)
		}

		for _, block := range excludeIPBlocks {
			excludeIPBlockMap[block.String()] = block
		}
	}
	return excludeIPBlockMap, nil
}

func isExcludeRoute(route *netlink.Route) bool {
	if route == nil {
		return false
	}
	return route.Type == unix.RTN_THROW
}

func combineSubnetInfoMap(a, b SubnetInfoMap) SubnetInfoMap {
	if len(b) == 0 {
		return a
	}

	res := make(map[string]*SubnetInfo, len(a)+len(b))
	for cidr, info := range a {
		res[cidr] = info
	}
	for cidr, info := range b {
		res[cidr] = info
	}

	return res
}

func combineNetMap(a, b map[string]*net.IPNet) map[string]*net.IPNet {
	if len(b) == 0 {
		return a
	}

	res := make(map[string]*net.IPNet, len(a)+len(b))
	for s, block := range a {
		res[s] = block
	}
	for s, block := range b {
		res[s] = block
	}

	return res
}
