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
	"net/http"
	"strings"
	"syscall"
	"time"

	daemonutils "github.com/alibaba/hybridnet/pkg/daemon/utils"

	"github.com/go-logr/logr"
	"github.com/heptiolabs/healthcheck"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/alibaba/hybridnet/pkg/daemon/bgp"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	multiclusterv1 "github.com/alibaba/hybridnet/pkg/apis/multicluster/v1"
	networkingv1 "github.com/alibaba/hybridnet/pkg/apis/networking/v1"
	"github.com/alibaba/hybridnet/pkg/constants"
	"github.com/alibaba/hybridnet/pkg/daemon/addr"
	daemonconfig "github.com/alibaba/hybridnet/pkg/daemon/config"
	"github.com/alibaba/hybridnet/pkg/daemon/iptables"
	"github.com/alibaba/hybridnet/pkg/daemon/neigh"
	"github.com/alibaba/hybridnet/pkg/daemon/route"
	"github.com/alibaba/hybridnet/pkg/feature"
)

const (
	InstanceIPIndex = "instanceIP"
	EndpointIPIndex = "endpointIP"

	NeighUpdateChanSize = 2000
	LinkUpdateChainSize = 200
	AddrUpdateChainSize = 200

	NetlinkSubscribeRetryInterval = 10 * time.Second
)

type CtrlHub struct {
	config *daemonconfig.Configuration
	mgr    ctrl.Manager

	subnetTriggerSourceForHostLink       *simpleTriggerSource
	subnetTriggerSourceForNodeInfoChange *simpleTriggerSource
	ipInstanceTriggerSourceForHostLink   *simpleTriggerSource
	nodeInfoTriggerSourceForHostAddr     *simpleTriggerSource

	routeV4Manager *route.Manager
	routeV6Manager *route.Manager

	neighV4Manager *neigh.Manager
	neighV6Manager *neigh.Manager

	addrV4Manager *addr.Manager

	bgpManager *bgp.Manager

	iptablesV4Manager  *iptables.Manager
	iptablesV6Manager  *iptables.Manager
	iptablesSyncCh     chan struct{}
	iptablesSyncTicker *time.Ticker

	nodeIPCache *NodeIPCache

	logger logr.Logger
}

func NewCtrlHub(config *daemonconfig.Configuration, mgr ctrl.Manager, logger logr.Logger) (*CtrlHub, error) {
	routeV4Manager, err := route.CreateRouteManager(config.LocalDirectTableNum,
		config.ToOverlaySubnetTableNum,
		config.OverlayMarkTableNum,
		netlink.FAMILY_V4,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create ipv4 route manager: %v", err)
	}

	routeV6Manager, err := route.CreateRouteManager(config.LocalDirectTableNum,
		config.ToOverlaySubnetTableNum,
		config.OverlayMarkTableNum,
		netlink.FAMILY_V6,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create ipv6 route manager: %v", err)
	}

	neighV4Manager := neigh.CreateNeighManager(netlink.FAMILY_V4)
	neighV6Manager := neigh.CreateNeighManager(netlink.FAMILY_V6)

	iptablesV4Manager, err := iptables.CreateIPtablesManager(iptables.ProtocolIpv4)
	if err != nil {
		return nil, fmt.Errorf("failed to create ipv4 iptables manager: %v", err)
	}

	iptablesV6Manager, err := iptables.CreateIPtablesManager(iptables.ProtocolIpv6)
	if err != nil {
		return nil, fmt.Errorf("failed to create ipv6 iptables manager: %v", err)
	}

	addrV4Manager := addr.CreateAddrManager(netlink.FAMILY_V4, config.NodeName)

	bgpManager, err := bgp.NewManager(config.NodeBGPIfName, config.BGPgRPCServerAddress, logger.WithName("bgp-server"))
	if err != nil {
		return nil, fmt.Errorf("failed to create bgp manager: %v", err)
	}

	ctrlHub := &CtrlHub{
		config: config,
		mgr:    mgr,

		subnetTriggerSourceForHostLink:       &simpleTriggerSource{key: "ForHostLinkEvent"},
		subnetTriggerSourceForNodeInfoChange: &simpleTriggerSource{key: "ForNodeInfo"},
		ipInstanceTriggerSourceForHostLink:   &simpleTriggerSource{key: "ForHostLinkEvent"},
		nodeInfoTriggerSourceForHostAddr:     &simpleTriggerSource{key: "ForHostAddr"},

		routeV4Manager: routeV4Manager,
		routeV6Manager: routeV6Manager,

		neighV4Manager: neighV4Manager,
		neighV6Manager: neighV6Manager,

		addrV4Manager: addrV4Manager,

		bgpManager: bgpManager,

		iptablesV4Manager:  iptablesV4Manager,
		iptablesV6Manager:  iptablesV6Manager,
		iptablesSyncCh:     make(chan struct{}, 1),
		iptablesSyncTicker: time.NewTicker(config.IptablesCheckDuration),

		nodeIPCache: NewNodeIPCache(),

		logger: logger,
	}

	thisNode := &corev1.Node{}
	if err = mgr.GetAPIReader().Get(context.TODO(), types.NamespacedName{Name: config.NodeName}, thisNode); err != nil {
		return nil, fmt.Errorf("failed to get node %s info %v", config.NodeName, err)
	}

	return ctrlHub, nil
}

func (c *CtrlHub) Run(ctx context.Context) error {
	c.runHealthyServer()

	if err := c.mgr.GetFieldIndexer().IndexField(context.TODO(), &networkingv1.IPInstance{},
		InstanceIPIndex, instanceIPIndexer); err != nil {
		return fmt.Errorf("failed to add instance ip indexer to manager: %v", err)
	}

	if feature.MultiClusterEnabled() {
		if err := c.mgr.GetFieldIndexer().IndexField(context.TODO(), &multiclusterv1.RemoteVtep{},
			EndpointIPIndex, endpointIPIndexer); err != nil {
			return fmt.Errorf("failed to add endpoint ip indexer to manager: %v", err)
		}
	}

	if err := (&subnetReconciler{
		Client:     c.mgr.GetClient(),
		ctrlHubRef: c,
	}).SetupWithManager(c.mgr); err != nil {
		return fmt.Errorf("failed to setup subnet controller: %v", err)
	}

	if err := (&ipInstanceReconciler{
		Client:     c.mgr.GetClient(),
		ctrlHubRef: c,
	}).SetupWithManager(c.mgr); err != nil {
		return fmt.Errorf("failed to setup ip instance controller: %v", err)
	}

	if err := (&nodeInfoReconciler{
		Client:     c.mgr.GetClient(),
		ctrlHubRef: c,
	}).SetupWithManager(c.mgr); err != nil {
		return fmt.Errorf("failed to setup node controller: %v", err)
	}

	if err := c.handleLocalNetworkDeviceEvent(); err != nil {
		return fmt.Errorf("failed to handle local network device event: %v", err)
	}

	if err := c.handleVxlanInterfaceNeighEvent(); err != nil {
		return fmt.Errorf("failed to handle vxlan interface neigh event: %v", err)
	}

	c.iptablesSyncLoop()

	if err := c.mgr.Start(ctx); err != nil {
		return fmt.Errorf("failed to start controller manager: %v", err)
	}
	return nil
}

func (c *CtrlHub) CacheSynced(ctx context.Context) bool {
	return c.mgr.GetCache().WaitForCacheSync(ctx)
}

func (c *CtrlHub) GetMgrClient() client.Client {
	return c.mgr.GetClient()
}

func (c *CtrlHub) GetMgrAPIReader() client.Reader {
	return c.mgr.GetAPIReader()
}

func (c *CtrlHub) GetBGPManager() *bgp.Manager {
	return c.bgpManager
}

// Once node network interface is set from down to up for some reasons, the routes and neigh caches for this interface
// will be cleaned, which should cause unrecoverable problems. Listening "UP" netlink events for interfaces and
// triggering subnet and ip instance reconcile loop will be the best way to recover routes and neigh caches.
//
// Restart of vxlan interface will also trigger subnet and ip instance reconcile loop.
func (c *CtrlHub) handleLocalNetworkDeviceEvent() error {
	hostNetNs, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get root netns: %v", err)
	}

	go func() {
		for {
			linkCh := make(chan netlink.LinkUpdate, LinkUpdateChainSize)
			doneCh := make(chan struct{})
			exitCh := make(chan struct{})

			errorCallback := func(err error) {
				c.logger.Error(err, "subscribe netlink link event exit with error")
				close(exitCh)
			}

			if err := netlink.LinkSubscribeWithOptions(linkCh, doneCh, netlink.LinkSubscribeOptions{
				Namespace:     &hostNetNs,
				ErrorCallback: errorCallback,
			}); err != nil {
				c.logger.Error(err, "failed to subscribe link update event")
				time.Sleep(NetlinkSubscribeRetryInterval)
				continue
			}

		linkLoop:
			for {
				select {
				case update := <-linkCh:
					if (update.IfInfomsg.Flags&unix.IFF_UP != 0) &&
						!daemonutils.CheckIfContainerNetworkLink(update.Link.Attrs().Name) {

						// Create event to flush routes and neigh caches.
						c.subnetTriggerSourceForHostLink.Trigger()
						c.ipInstanceTriggerSourceForHostLink.Trigger()
					}
				case <-exitCh:
					close(doneCh)
					break linkLoop
				}
			}
		}
	}()

	go func() {
		for {
			addrCh := make(chan netlink.AddrUpdate, AddrUpdateChainSize)
			doneCh := make(chan struct{})
			exitCh := make(chan struct{})

			errorCallback := func(err error) {
				c.logger.Error(err, "subscribe netlink addr event exit with error")
				close(exitCh)
			}

			if err := netlink.AddrSubscribeWithOptions(addrCh, doneCh, netlink.AddrSubscribeOptions{
				Namespace:     &hostNetNs,
				ErrorCallback: errorCallback,
			}); err != nil {
				c.logger.Error(err, "failed to subscribe address update event")
				time.Sleep(NetlinkSubscribeRetryInterval)
				continue
			}

		addrLoop:
			for {
				select {
				case update := <-addrCh:
					link, err := netlink.LinkByIndex(update.LinkIndex)
					if err != nil {
						c.logger.Error(err, "failed to get link by addr update event link index", "addr",
							update.LinkAddress, "link index", update.LinkIndex)
						continue
					}

					if daemonutils.CheckIPIsGlobalUnicast(update.LinkAddress.IP) &&
						!daemonutils.CheckIfContainerNetworkLink(link.Attrs().Name) {
						// Create event to update node configuration.
						c.nodeInfoTriggerSourceForHostAddr.Trigger()
					}
				case <-exitCh:
					close(doneCh)
					break addrLoop
				}
			}
		}
	}()

	return nil
}

func (c *CtrlHub) handleVxlanInterfaceNeighEvent() error {

	ipSearch := func(ip net.IP, link netlink.Link) error {
		var vtepMac net.HardwareAddr

		if mac, exist := c.nodeIPCache.SearchIP(ip); exist {
			// find node ip.
			vtepMac = mac
		} else {
			ipInstance, err := c.getIPInstanceByAddress(ip)
			if err != nil {
				return fmt.Errorf("failed to get ip instance by address %v: %v", ip.String(), err)
			}

			if ipInstance != nil {
				nodeInfo := &networkingv1.NodeInfo{}
				nodeName := ipInstance.Labels[constants.LabelNode]

				if err := c.mgr.GetClient().Get(context.TODO(), types.NamespacedName{Name: nodeName}, nodeInfo); err != nil {
					return fmt.Errorf("failed to get node %v: %v", nodeName, err)
				}

				if nodeInfo.Spec.VTEPInfo == nil {
					return fmt.Errorf("node info of %v is nil", nodeName)
				}

				vtepMac, err = net.ParseMAC(nodeInfo.Spec.VTEPInfo.MAC)
				if err != nil {
					return fmt.Errorf("failed to parse vtep mac %v: %v",
						nodeInfo.Spec.VTEPInfo.MAC, err)
				}
			} else if feature.MultiClusterEnabled() {
				// try to find remote vtep according to pod ip
				vtep, err := c.getRemoteVtepByEndpointAddress(ip)
				if err != nil {
					return fmt.Errorf("failed to get remote vtep by address %s: %v", ip.String(), err)
				}

				if vtep != nil {
					vtepMac, err = net.ParseMAC(vtep.Spec.VTEPInfo.MAC)
					if err != nil {
						return fmt.Errorf("failed to parse vtep mac %v: %v", vtep.Spec.VTEPInfo.MAC, err)
					}
				}
			}
		}

		if len(vtepMac) == 0 {
			// if ip not exist, try to clear it's neigh entries
			if err := neigh.ClearStaleNeighEntryByIP(link.Attrs().Index, ip); err != nil {
				return fmt.Errorf("failed to clear stale neigh for link %v and ip %v: %v",
					link.Attrs().Name, ip.String(), err)
			}

			return fmt.Errorf("no matched node or pod ip cache found for ip %v", ip.String())
		}

		neighEntry := netlink.Neigh{
			LinkIndex:    link.Attrs().Index,
			State:        netlink.NUD_REACHABLE,
			Type:         syscall.RTN_UNICAST,
			IP:           ip,
			HardwareAddr: vtepMac,
		}
		if err := netlink.NeighSet(&neighEntry); err != nil {
			return fmt.Errorf("failed to set neigh %v: %v", neighEntry.String(), err)
		}

		c.logger.V(4).Info("neigh proxy resolve success", "ip", ip.String(), "mac", vtepMac.String())

		return nil
	}

	ipSearchExecWrapper := func(ip net.IP, link netlink.Link) {
		if err := ipSearch(ip, link); err != nil {
			// print as info
			c.logger.Info("failed to proxy resolve overlay neigh", "message", err)
		}
	}

	hostNetNs, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get root netns: %v", err)
	}

	timer := time.NewTicker(c.config.VxlanExpiredNeighCachesClearInterval)
	errorMessageWrapper := initErrorMessageWrapper("failed to handle vxlan interface neigh event: ")

	go func() {
		for {
			// Clear stale and failed neigh entries for vxlan interface at the first time.
			// Once neigh subscribe failed (include the goroutine exit), it's most probably because of
			// "No buffer space available" problem, we need to clean expired neigh caches.
			if err := clearVxlanExpiredNeighCaches(); err != nil {
				c.logger.Error(err, "failed to clear vxlan expired neigh caches")
			}

			neighCh := make(chan netlink.NeighUpdate, NeighUpdateChanSize)
			doneCh := make(chan struct{})
			exitCh := make(chan struct{})

			errorCallback := func(err error) {
				c.logger.Error(err, "subscribe netlink neigh event exit with error")
				close(exitCh)
			}

			if err := netlink.NeighSubscribeWithOptions(neighCh, doneCh, netlink.NeighSubscribeOptions{
				Namespace:     &hostNetNs,
				ErrorCallback: errorCallback,
			}); err != nil {
				c.logger.Error(err, "failed to subscribe neigh update event")
				time.Sleep(NetlinkSubscribeRetryInterval)
				continue
			}

		neighLoop:
			for {
				select {
				case update := <-neighCh:
					if isNeighResolving(update.State) {
						if update.Type == syscall.RTM_DELNEIGH {
							continue
						}

						link, err := netlink.LinkByIndex(update.LinkIndex)
						if err != nil {
							c.logger.Error(err, errorMessageWrapper("failed to get link by index %v", update.LinkIndex))
							continue
						}

						if strings.Contains(link.Attrs().Name, constants.VxlanLinkInfix) {
							go ipSearchExecWrapper(update.IP, link)
						}
					}
				case <-timer.C:
					if err := clearVxlanExpiredNeighCaches(); err != nil {
						c.logger.Error(err, "failed to clear vxlan expired neigh caches")
					}
				case <-exitCh:
					close(doneCh)
					break neighLoop
				}
			}
		}
	}()

	return nil
}

func (c *CtrlHub) iptablesSyncLoop() {
	iptablesSyncFunc := func() error {
		c.iptablesV4Manager.Reset()
		c.iptablesV6Manager.Reset()

		networkList := &networkingv1.NetworkList{}
		if err := c.mgr.GetClient().List(context.TODO(), networkList); err != nil {
			return fmt.Errorf("failed to list network: %v", err)
		}

		for _, network := range networkList.Items {
			switch networkingv1.GetNetworkMode(&network) {
			case networkingv1.NetworkModeVxlan:
				netID := network.Spec.NetID

				overlayIfName, err := daemonutils.GenerateVxlanNetIfName(c.config.NodeVxlanIfName, netID)
				if err != nil {
					return fmt.Errorf("failed to generate vxlan forward node if name: %v", err)
				}

				c.iptablesV4Manager.SetOverlayIfName(overlayIfName)
				c.iptablesV6Manager.SetOverlayIfName(overlayIfName)
			case networkingv1.NetworkModeBGP:
				if nodeBelongsToNetwork(c.config.NodeName, &network) {
					c.iptablesV4Manager.SetBgpIfName(c.config.NodeBGPIfName)
					c.iptablesV6Manager.SetBgpIfName(c.config.NodeBGPIfName)
				}
			}
		}

		// Record node ips.
		nodeInfoList := &networkingv1.NodeInfoList{}
		if err := c.mgr.GetClient().List(context.TODO(), nodeInfoList); err != nil {
			return fmt.Errorf("failed to list node: %v", err)
		}

		for _, nodeInfo := range nodeInfoList.Items {
			// Underlay only environment should not print output
			if nodeInfo.Spec.VTEPInfo == nil ||
				len(nodeInfo.Spec.VTEPInfo.MAC) == 0 ||
				len(nodeInfo.Spec.VTEPInfo.IP) == 0 ||
				len(nodeInfo.Spec.VTEPInfo.LocalIPs) == 0 {
				c.logger.Info("node's vtep information has not been updated", "node", nodeInfo.Name)
				continue
			}

			if nodeInfo.Name == c.config.NodeName {
				for _, ipString := range nodeInfo.Spec.VTEPInfo.LocalIPs {
					ip := net.ParseIP(ipString)
					if ip.To4() != nil {
						// v4 address
						c.iptablesV4Manager.RecordLocalNodeIP(ip)
					} else {
						// v6 address
						c.iptablesV6Manager.RecordLocalNodeIP(ip)
					}
				}
			}

			for _, ipString := range nodeInfo.Spec.VTEPInfo.LocalIPs {
				ip := net.ParseIP(ipString)
				if ip.To4() != nil {
					// v4 address
					c.iptablesV4Manager.RecordNodeIP(ip)
				} else {
					// v6 address
					c.iptablesV6Manager.RecordNodeIP(ip)
				}
			}
		}

		// Record local pod ip.
		ipInstanceList := &networkingv1.IPInstanceList{}
		if err := c.mgr.GetClient().List(context.TODO(), ipInstanceList,
			client.MatchingLabels{constants.LabelNode: c.config.NodeName}); err != nil {
			return fmt.Errorf("failed to list pod ip instances of node %v: %v", c.config.NodeName, err)
		}

		for _, ipInstance := range ipInstanceList.Items {
			// skip reserved ip instance
			if networkingv1.IsReserved(&ipInstance) {
				continue
			}

			// skip terminating ip instance
			if ipInstance.DeletionTimestamp != nil {
				continue
			}

			podIP, _, err := net.ParseCIDR(ipInstance.Spec.Address.IP)
			if err != nil {
				return fmt.Errorf("parse pod ip %v error: %v", ipInstance.Spec.Address.IP, err)
			}

			if podIP.To4() == nil {
				c.iptablesV6Manager.RecordLocalPodIP(podIP)
			} else {
				c.iptablesV4Manager.RecordLocalPodIP(podIP)
			}
		}

		// Record local subnet cidr.
		subnetList := &networkingv1.SubnetList{}
		if err := c.mgr.GetClient().List(context.TODO(), subnetList); err != nil {
			return fmt.Errorf("failed to list subnet: %v", err)
		}

		for _, subnet := range subnetList.Items {
			_, cidr, err := net.ParseCIDR(subnet.Spec.Range.CIDR)
			if err != nil {
				return fmt.Errorf("failed to parse subnet cidr %v: %v", subnet.Spec.Range.CIDR, err)
			}

			network := &networkingv1.Network{}
			if err := c.mgr.GetClient().Get(context.TODO(), types.NamespacedName{Name: subnet.Spec.Network}, network); err != nil {
				return fmt.Errorf("failed to get network for subnet %v", subnet.Name)
			}

			iptablesManager := c.getIPtablesManager(subnet.Spec.Range.Version)

			// isLocal means whether this node belongs to this network
			isLocal := nodeBelongsToNetwork(c.config.NodeName, network)

			// if network is local vlan, record vlan forward interface names
			if isLocal && networkingv1.GetNetworkMode(network) == networkingv1.NetworkModeVlan {
				netID := subnet.Spec.NetID
				if netID == nil {
					netID = network.Spec.NetID
				}

				vlanForwardIfName, err := daemonutils.GenerateVlanNetIfName(c.config.NodeVlanIfName, netID)
				if err != nil {
					c.logger.Error(err, "failed to generate vlan network interface name", "vlanMasterInterface", c.config.NodeVlanIfName, "netID", netID)
					continue
				}

				iptablesManager.RecordVlanForwardIfName(vlanForwardIfName)
			}

			iptablesManager.RecordSubnet(cidr,
				networkingv1.GetNetworkType(network) == networkingv1.NetworkTypeOverlay,
				isLocal)
		}

		if feature.MultiClusterEnabled() {
			// If remote overlay network des not exist, the rcmanager will not fetch
			// RemoteSubnet and RemoteVtep. Thus, existence check is redundant here.

			remoteSubnetList := &multiclusterv1.RemoteSubnetList{}
			if err := c.mgr.GetClient().List(context.TODO(), remoteSubnetList); err != nil {
				return fmt.Errorf("failed to list remote network: %v", err)
			}

			// Record remote vtep ip.
			vtepList := &multiclusterv1.RemoteVtepList{}
			if err := c.mgr.GetClient().List(context.TODO(), vtepList); err != nil {
				return fmt.Errorf("failed to list remote vtep: %v", err)
			}

			for _, vtep := range vtepList.Items {
				if len(vtep.Spec.VTEPInfo.LocalIPs) == 0 {
					ip := net.ParseIP(vtep.Spec.VTEPInfo.IP)
					if ip.To4() != nil {
						// v4 address
						c.iptablesV4Manager.RecordRemoteNodeIP(ip)
					} else {
						// v6 address
						c.iptablesV6Manager.RecordRemoteNodeIP(ip)
					}
					continue
				}

				for _, ipString := range vtep.Spec.VTEPInfo.LocalIPs {
					ip := net.ParseIP(ipString)
					if ip.To4() != nil {
						// v4 address
						c.iptablesV4Manager.RecordRemoteNodeIP(ip)
					} else {
						// v6 address
						c.iptablesV6Manager.RecordRemoteNodeIP(ip)
					}
				}
			}

			// Record remote subnet cidr
			for _, remoteSubnet := range remoteSubnetList.Items {
				_, cidr, err := net.ParseCIDR(remoteSubnet.Spec.Range.CIDR)
				if err != nil {
					return fmt.Errorf("failed to parse remote subnet cidr %v: %v", remoteSubnet.Spec.Range.CIDR, err)
				}

				c.getIPtablesManager(remoteSubnet.Spec.Range.Version).
					RecordRemoteSubnet(cidr, multiclusterv1.GetRemoteSubnetType(&remoteSubnet) == networkingv1.NetworkTypeOverlay)
			}
		}

		// Sync rules.
		if err := c.iptablesV4Manager.SyncRules(); err != nil {
			return fmt.Errorf("failed to sync v4 iptables rule: %v", err)
		}

		globalDisabled, err := daemonutils.CheckIPv6GlobalDisabled()
		if err != nil {
			return fmt.Errorf("failed to check ipv6 global disabled: %v", err)
		}

		if !globalDisabled {
			if err := c.iptablesV6Manager.SyncRules(); err != nil {
				return fmt.Errorf("failed to sync v6 iptables rule: %v", err)
			}
		}

		return nil
	}

	go func() {
		for {
			select {
			case <-c.iptablesSyncCh:
				if err := iptablesSyncFunc(); err != nil {
					c.logger.Error(err, "failed to sync iptables rule")
				}
			case <-c.iptablesSyncTicker.C:
				c.iptablesSyncTrigger()
			}
		}
	}()
}

func (c *CtrlHub) iptablesSyncTrigger() {
	select {
	case c.iptablesSyncCh <- struct{}{}:
	default:
	}
}

func (c *CtrlHub) runHealthyServer() {
	health := healthcheck.NewHandler()

	go func() {
		_ = http.ListenAndServe(c.config.HealthyServerAddress, health)
	}()

	c.logger.Info("start healthy server", "bind-address", c.config.HealthyServerAddress)
}

func isNeighResolving(state int) bool {
	// We need a neigh cache to be STALE if it's not used for a while.
	return (state & netlink.NUD_INCOMPLETE) != 0
}

func instanceIPIndexer(obj client.Object) []string {
	instance, ok := obj.(*networkingv1.IPInstance)
	if ok {
		podIP, _, err := net.ParseCIDR(instance.Spec.Address.IP)
		if err != nil {
			return []string{}
		}

		return []string{podIP.String()}
	}
	return []string{}
}

func endpointIPIndexer(obj client.Object) []string {
	vtep, ok := obj.(*multiclusterv1.RemoteVtep)
	if ok {
		endpointIPs := vtep.Spec.EndpointIPList
		if len(endpointIPs) > 0 {
			return endpointIPs
		}
	}
	return []string{}
}

func clearVxlanExpiredNeighCaches() error {
	linkList, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("failed to list link: %v", err)
	}

	for _, link := range linkList {
		if strings.Contains(link.Attrs().Name, constants.VxlanLinkInfix) {
			if err := neigh.ClearStaleAddFailedNeighEntries(link.Attrs().Index, netlink.FAMILY_V4); err != nil {
				return fmt.Errorf("failed to clear v4 expired neigh entries for link %v: %v",
					link.Attrs().Name, err)
			}

			ipv6Disabled, err := daemonutils.CheckIPv6Disabled(link.Attrs().Name)
			if err != nil {
				return fmt.Errorf("failed to check ipv6 disables for link %v: %v", link.Attrs().Name, err)
			}

			if !ipv6Disabled {
				if err := neigh.ClearStaleAddFailedNeighEntries(link.Attrs().Index, netlink.FAMILY_V6); err != nil {
					return fmt.Errorf("failed to clear v6 expired neigh entries for link %v: %v",
						link.Attrs().Name, err)
				}
			}
		}
	}

	return nil
}
