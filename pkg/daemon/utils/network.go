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

package utils

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/alibaba/hybridnet/pkg/constants"

	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"
)

type IPInfo struct {
	Addr  net.IP
	Gw    net.IP
	Cidr  *net.IPNet
	NetID *int32
}

func GenerateVlanNetIfName(parentName string, vlanID *int32) (string, error) {
	if vlanID == nil {
		return "", fmt.Errorf("vlan id should not be nil")
	}

	if *vlanID > 4096 {
		return "", fmt.Errorf("vlan id's value range is from 0 to 4094")
	}

	if *vlanID == 0 {
		return parentName, nil
	}

	return fmt.Sprintf("%s.%v", parentName, *vlanID), nil
}

func GenerateVxlanNetIfName(parentName string, vlanID *int32) (string, error) {
	if vlanID == nil || *vlanID == 0 {
		return "", fmt.Errorf("vxlan id should not be nil or zero")
	}

	maxVxlanID := int32(1<<24 - 1)
	if *vlanID > maxVxlanID {
		return "", fmt.Errorf("vxlan id's value range is from 1 to %d", maxVxlanID)
	}

	return fmt.Sprintf("%s%s%v", parentName, constants.VxlanLinkInfix, *vlanID), nil
}

func EnsureVlanIf(nodeIfName string, vlanID *int32) (string, error) {
	nodeIf, err := netlink.LinkByName(nodeIfName)
	if err != nil {
		return "", err
	}

	vlanIfName, err := GenerateVlanNetIfName(nodeIfName, vlanID)
	if err != nil {
		return "", fmt.Errorf("failed to ensure bridge: %v", err)
	}

	// create the vlan interface if not exist
	var vlanIf netlink.Link
	if vlanIf, err = netlink.LinkByName(vlanIfName); err != nil {
		if vlanIfName == nodeIfName {
			// Pod in the same vlan with node.
			return vlanIfName, nil
		}

		vif := &netlink.Vlan{
			VlanId:    int(*vlanID),
			LinkAttrs: netlink.NewLinkAttrs(),
		}
		vif.ParentIndex = nodeIf.Attrs().Index
		vif.Name = vlanIfName

		err = netlink.LinkAdd(vif)
		if err != nil {
			return vlanIfName, err
		}

		vlanIf, err = netlink.LinkByName(vlanIfName)
		if err != nil {
			return vlanIfName, err
		}
	}

	// setup the vlan (or node interface) if it's not UP
	if err = netlink.LinkSetUp(vlanIf); err != nil {
		return vlanIfName, err
	}

	return vlanIfName, nil
}

func GetDefaultInterface(family int) (*net.Interface, error) {
	defaultRoute, err := GetDefaultRoute(family)
	if err != nil {
		return nil, err
	}

	if defaultRoute.LinkIndex <= 0 {
		return nil, errors.New("found ipv4 default route but could not determine interface")
	}

	iface, err := net.InterfaceByIndex(defaultRoute.LinkIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %v", err)
	}

	return iface, nil
}

func GetDefaultRoute(family int) (*netlink.Route, error) {
	routes, err := netlink.RouteList(nil, family)
	if err != nil {
		return nil, err
	}

	for _, route := range routes {
		if IsDefaultRoute(&route, family) {
			return &route, nil
		}
	}

	return nil, NotExist
}

func IsDefaultRoute(route *netlink.Route, family int) bool {
	if route == nil {
		return false
	}

	defaultDstString := "0.0.0.0/0"
	if family == netlink.FAMILY_V6 {
		defaultDstString = "::/0"
	}

	return route.Dst == nil || route.Dst.String() == defaultDstString
}

// GetInterfaceByPreferString return first valid interface by prefer string.
func GetInterfaceByPreferString(preferString string) (*net.Interface, error) {
	ifList := strings.Split(preferString, ",")
	for _, iF := range ifList {
		if iF == "" {
			continue
		}

		iif, err := net.InterfaceByName(iF)
		if err == nil {
			return iif, nil
		}
	}

	return nil, fmt.Errorf("no valid interface found by prefer string %v", preferString)
}

func GenerateIPListString(addrList []netlink.Addr) string {
	ipListString := ""
	for _, addr := range addrList {
		if ipListString == "" {
			ipListString = addr.IP.String()
			continue
		}
		ipListString = ipListString + "," + addr.IP.String()
	}

	return ipListString
}

func ListAllAddress(link netlink.Link) ([]netlink.Addr, error) {
	var addrList []netlink.Addr

	ipv4AddrList, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("failed to list ipv4 address for link %v: %v", link.Attrs().Name, err)
	}

	ipv6AddrList, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return nil, fmt.Errorf("failed to list ipv6 address for link %v: %v", link.Attrs().Name, err)
	}

	for _, addr := range ipv4AddrList {
		if CheckIPIsGlobalUnicast(addr.IP) {
			addrList = append(addrList, addr)
		}
	}

	for _, addr := range ipv6AddrList {
		if CheckIPIsGlobalUnicast(addr.IP) {
			addrList = append(addrList, addr)
		}
	}

	return addrList, nil
}

func CheckIPIsGlobalUnicast(ip net.IP) bool {
	return !ip.IsInterfaceLocalMulticast() && ip.IsGlobalUnicast()
}

func CheckPodRuleExist(podCidr *net.IPNet, family int) (bool, int, error) {
	ruleList, err := netlink.RuleList(family)
	if err != nil {
		return false, 0, fmt.Errorf("failed to list rule: %v", err)
	}

	for _, rule := range ruleList {
		if rule.Src != nil && podCidr.String() == rule.Src.String() {
			return true, rule.Table, nil
		}
	}

	return false, 0, nil
}

func CheckDefaultRouteExist(table int, family int) (bool, error) {
	routeList, err := netlink.RouteListFiltered(family, &netlink.Route{
		Table: table,
	}, netlink.RT_FILTER_TABLE)

	if err != nil {
		return false, fmt.Errorf("failed to list route for table %v", table)
	}

	for _, route := range routeList {
		if IsDefaultRoute(&route, family) {
			return true, nil
		}
	}

	return false, nil
}

func CheckPodNeighExist(podIP net.IP, forwardNodeIfIndex int, family int) (bool, error) {
	neighList, err := netlink.NeighProxyList(forwardNodeIfIndex, family)
	if err != nil {
		return false, fmt.Errorf("failed to list neighs for forward node if index %v: %v", forwardNodeIfIndex, err)
	}

	for _, neigh := range neighList {
		if neigh.IP.Equal(podIP) {
			return true, nil
		}
	}

	return false, nil
}

// AddRoute adds a universally-scoped route. If no direct route contains gw IP, add single route for gw.
func AddRoute(ipn *net.IPNet, gw net.IP, dev netlink.Link) error {
	ipFamily := netlink.FAMILY_V4
	ipMask := net.CIDRMask(32, 32)
	if gw.To4() == nil {
		ipFamily = netlink.FAMILY_V6
		ipMask = net.CIDRMask(128, 128)
	}

	routeList, err := netlink.RouteList(dev, ipFamily)
	if err != nil {
		return fmt.Errorf("failed to list route on dev %v: %v", dev.Attrs().Name, err)
	}

	containsGW := false
	for _, route := range routeList {
		if route.Dst != nil && route.Dst.Contains(gw) {
			containsGW = true
			break
		}
	}

	if !containsGW {
		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: dev.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst: &net.IPNet{
				IP:   gw,
				Mask: ipMask,
			},
		}); err != nil {
			return fmt.Errorf("failed to add direct route for gw ip %v: %v", gw.String(), err)
		}
	}

	return netlink.RouteAdd(&netlink.Route{
		LinkIndex: dev.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Dst:       ipn,
		Gw:        gw,
	})
}

func EnableIPForward(family int) error {
	if family == netlink.FAMILY_V4 {
		return ip.EnableIP4Forward()
	}
	return ip.EnableIP6Forward()
}

func EnsureNeighGCThresh(family int, neighGCThresh1, neighGCThresh2, neighGCThresh3 int) error {
	if family == netlink.FAMILY_V4 {
		// From kernel doc:
		// neigh/default/gc_thresh1 - INTEGER
		//     Minimum number of entries to keep.  Garbage collector will not
		//     purge entries if there are fewer than this number.
		//     Default: 128
		if err := SetSysctl(constants.IPv4NeighGCThresh1, neighGCThresh1); err != nil {
			return fmt.Errorf("failed to set %s sysctl path to %v, error: %v", constants.IPv4NeighGCThresh1, neighGCThresh1, err)
		}

		// From kernel doc:
		// neigh/default/gc_thresh2 - INTEGER
		//     Threshold when garbage collector becomes more aggressive about
		//     purging entries. Entries older than 5 seconds will be cleared
		//     when over this number.
		//     Default: 512
		if err := SetSysctl(constants.IPv4NeighGCThresh2, neighGCThresh2); err != nil {
			return fmt.Errorf("failed to set %s sysctl path to %v, error: %v", constants.IPv4NeighGCThresh2, neighGCThresh2, err)
		}

		// From kernel doc:
		// neigh/default/gc_thresh3 - INTEGER
		//     Maximum number of neighbor entries allowed.  Increase this
		//     when using large numbers of interfaces and when communicating
		//     with large numbers of directly-connected peers.
		//     Default: 1024
		if err := SetSysctl(constants.IPv4NeighGCThresh3, neighGCThresh3); err != nil {
			return fmt.Errorf("failed to set %s sysctl path to %v, error: %v", constants.IPv4NeighGCThresh3, neighGCThresh3, err)
		}

		return nil
	}

	if err := SetSysctl(constants.IPv6NeighGCThresh1, neighGCThresh1); err != nil {
		return fmt.Errorf("failed to set %s sysctl path to %v, error: %v", constants.IPv6NeighGCThresh1, neighGCThresh1, err)
	}

	if err := SetSysctl(constants.IPv6NeighGCThresh2, neighGCThresh2); err != nil {
		return fmt.Errorf("failed to set %s sysctl path to %v, error: %v", constants.IPv6NeighGCThresh2, neighGCThresh2, err)
	}

	if err := SetSysctl(constants.IPv6NeighGCThresh3, neighGCThresh3); err != nil {
		return fmt.Errorf("failed to set %s sysctl path to %v, error: %v", constants.IPv6NeighGCThresh3, neighGCThresh3, err)
	}

	return nil
}

func EnsureIPv6RouteGCParameters(routeCacheMaxSize, gcThresh int) error {
	// IPv6 traffic's being dropped happens suddenly in some kernel versions (e.g., 4.18.0-80.el8.x86_64 of CentOS 8), while
	// running "ip route get" for some of the ipv6 routes in table 39999 you can get a "Network is unreachable" error (though
	// you can see a obviously correct route table configuration by running "ip route show"), and all neighbors are
	// invalidated at the same time. This problem will shutdown all the Pods' network on the same node.
	//
	// We believed that this problem is related to the kernel GC mechanism of ipv6 route cache because errors disappeared
	// when the "net.ipv6.route.max_size" kernel parameter was configured to a much larger one (default 4096). But no related
	// kernel patch is founded.

	if err := SetSysctl(constants.IPv6RouteCacheMaxSizeSysctl, routeCacheMaxSize); err != nil {
		return fmt.Errorf("failed to set %s sysctl path to %v, error: %v", constants.IPv6RouteCacheMaxSizeSysctl, routeCacheMaxSize, err)
	}

	if err := SetSysctl(constants.IPv6RouteCacheGCThresh, gcThresh); err != nil {
		return fmt.Errorf("failed to set %s sysctl path to %v, error: %v", constants.IPv6RouteCacheGCThresh, gcThresh, err)
	}
	return nil
}

func CheckIPv6GlobalDisabled() (bool, error) {
	moduleDisableVar, err := GetSysctl(constants.IPv6DisableModuleParameter)
	if err != nil {
		return false, err
	}

	if moduleDisableVar == 1 {
		return true, nil
	}

	sysctlGlobalDisableVar, err := GetSysctl(fmt.Sprintf(constants.IPv6DisableSysctl, "all"))
	if err != nil {
		return false, err
	}

	if sysctlGlobalDisableVar == 1 {
		return true, nil
	}

	return false, nil
}

func CheckIPv6Disabled(nicName string) (bool, error) {
	globalDisabled, err := CheckIPv6GlobalDisabled()
	if err != nil {
		return false, err
	}

	if globalDisabled {
		return true, nil
	}

	sysctlDisableVar, err := GetSysctl(fmt.Sprintf(constants.IPv6DisableSysctl, nicName))
	if err != nil {
		return false, err
	}

	if sysctlDisableVar == 1 {
		return true, nil
	}

	return false, nil
}

// ConfigureIface takes the result of IPAM plugin and
// applies to the ifName interface.
func ConfigureIface(ifName string, res *current.Result) error {
	if len(res.Interfaces) == 0 {
		return fmt.Errorf("no interfaces to configure")
	}

	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set %q UP: %v", ifName, err)
	}

	var v4gw, v6gw net.IP
	var hasEnabledIPv6 = false
	for _, ipc := range res.IPs {
		if ipc.Interface == nil {
			continue
		}
		intIdx := *ipc.Interface
		if intIdx < 0 || intIdx >= len(res.Interfaces) || res.Interfaces[intIdx].Name != ifName {
			// IP address is for a different interface
			return fmt.Errorf("failed to add IP addr %v to %q: invalid interface index", ipc, ifName)
		}

		// Make sure sysctl "disable_ipv6" is 0 if we are about to add
		// an IPv6 address to the interface
		if !hasEnabledIPv6 && ipc.Version == "6" {
			// Enabled IPv6 for loopback "lo" and the interface
			// being configured
			for _, iface := range [2]string{"lo", ifName} {
				ipv6SysctlValueName := fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6", iface)

				// Read current sysctl value
				value, err := sysctl.Sysctl(ipv6SysctlValueName)
				if err != nil || value == "0" {
					// FIXME: log warning if unable to read sysctl value
					continue
				}

				// Write sysctl to enable IPv6
				_, err = sysctl.Sysctl(ipv6SysctlValueName, "0")
				if err != nil {
					return fmt.Errorf("failed to enable IPv6 for interface %q (%s=%s): %v", iface, ipv6SysctlValueName, value, err)
				}
			}
			hasEnabledIPv6 = true
		}

		addr := &netlink.Addr{
			IPNet: &ipc.Address,
			Label: "",
			Flags: unix.IFA_F_NOPREFIXROUTE,
		}
		if err = netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("failed to add IP addr %v to %q: %v", ipc, ifName, err)
		}

		gwIsV4 := ipc.Gateway.To4() != nil
		if gwIsV4 && v4gw == nil {
			v4gw = ipc.Gateway
		} else if !gwIsV4 && v6gw == nil {
			v6gw = ipc.Gateway
		}
	}

	if v6gw != nil {
		if err = ip.SettleAddresses(ifName, 10); err != nil {
			return fmt.Errorf("failed to settle address on %s: %v", ifName, err)
		}
	}

	for _, r := range res.Routes {
		routeIsV4 := r.Dst.IP.To4() != nil
		gw := r.GW
		if gw == nil {
			if routeIsV4 && v4gw != nil {
				gw = v4gw
			} else if !routeIsV4 && v6gw != nil {
				gw = v6gw
			}
		}
		if err = AddRoute(&r.Dst, gw, link); err != nil {
			// we skip over duplicate routes as we assume the first one wins
			if !os.IsExist(err) {
				return fmt.Errorf("failed to add route '%v via %v dev %v': %v", r.Dst, gw, ifName, err)
			}
		}
	}

	return nil
}

func EnsureIPReachable(ip net.IP) error {
	ipMask := net.CIDRMask(32, 32)
	if ip.To4() == nil {
		ipMask = net.CIDRMask(128, 128)
	}

	routeList, _ := netlink.RouteGet(ip)
	// netlink.RouteGet will return an error if ip is unreachable
	if len(routeList) > 0 {
		return nil
	}

	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("failed to get loopback dev: %v", err)
	}

	if err = netlink.RouteAdd(&netlink.Route{
		Scope: netlink.SCOPE_LINK,
		Dst: &net.IPNet{
			IP:   ip,
			Mask: ipMask,
		},
		LinkIndex: loopback.Attrs().Index,
	}); err != nil {
		return err
	}

	return nil
}
