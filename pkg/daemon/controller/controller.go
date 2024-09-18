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

	networkingv1 "github.com/alibaba/hybridnet/pkg/apis/networking/v1"
	hybridnetinformer "github.com/alibaba/hybridnet/pkg/client/informers/externalversions"
	networkinglister "github.com/alibaba/hybridnet/pkg/client/listers/networking/v1"
	"github.com/alibaba/hybridnet/pkg/constants"
	"github.com/alibaba/hybridnet/pkg/daemon/addr"
	daemonconfig "github.com/alibaba/hybridnet/pkg/daemon/config"
	"github.com/alibaba/hybridnet/pkg/daemon/containernetwork"
	"github.com/alibaba/hybridnet/pkg/daemon/iptables"
	"github.com/alibaba/hybridnet/pkg/daemon/neigh"
	"github.com/alibaba/hybridnet/pkg/daemon/route"
	"github.com/alibaba/hybridnet/pkg/feature"
	"github.com/heptiolabs/healthcheck"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	corev1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
)

const (
	ActionReconcileSubnet     = "ReconcileSubnet"
	ActionReconcileIPInstance = "ReconcileIPInstance"
	ActionReconcileNode       = "ReconcileNode"

	ByInstanceIPIndexer = "instanceIP"
	ByEndpointIPIndexer = "endpointIP"

	// to reduce channel block times while neigh netlink update increase.
	NeighUpdateChanSize = 2000
	LinkUpdateChainSize = 200
	AddrUpdateChainSize = 200

	NetlinkSubscribeRetryInterval = 10 * time.Second
)

// Controller is a set of kubernetes controllers
type Controller struct {
	subnetLister networkinglister.SubnetLister
	subnetSynced cache.InformerSynced
	subnetQueue  workqueue.RateLimitingInterface

	ipInstanceLister  networkinglister.IPInstanceLister
	ipInstanceSynced  cache.InformerSynced
	ipInstanceQueue   workqueue.RateLimitingInterface
	ipInstanceIndexer cache.Indexer

	networkLister networkinglister.NetworkLister
	networkSynced cache.InformerSynced

	nodeLister corev1.NodeLister
	nodeSynced cache.InformerSynced
	nodeQueue  workqueue.RateLimitingInterface

	// cluster-mesh related crd: RemoteSubnet
	remoteSubnetLister networkinglister.RemoteSubnetLister
	remoteSubnetSynced cache.InformerSynced

	// cluster-mesh related crd: RemoteVtep
	remoteVtepLister  networkinglister.RemoteVtepLister
	remoteVtepSynced  cache.InformerSynced
	remoteVtepIndexer cache.Indexer

	config *daemonconfig.Configuration

	routeV4Manager *route.Manager
	routeV6Manager *route.Manager

	neighV4Manager *neigh.Manager
	neighV6Manager *neigh.Manager

	addrV4Manager *addr.Manager

	iptablesV4Manager  *iptables.Manager
	iptablesV6Manager  *iptables.Manager
	iptablesSyncCh     chan struct{}
	iptablesSyncTicker *time.Ticker

	nodeIPCache *NodeIPCache

	upgradeWorkDone bool
}

// NewController returns a Controller to watch kubernetes CRD object events
func NewController(config *daemonconfig.Configuration,
	hybridnetInformerFactory hybridnetinformer.SharedInformerFactory,
	kubeInformerFactory informers.SharedInformerFactory) (*Controller, error) {

	subnetInformer := hybridnetInformerFactory.Networking().V1().Subnets()
	networkInformer := hybridnetInformerFactory.Networking().V1().Networks()
	ipInstanceInformer := hybridnetInformerFactory.Networking().V1().IPInstances()
	nodeInformer := kubeInformerFactory.Core().V1().Nodes()

	routeV4Manager, err := route.CreateRouteManager(config.LocalDirectTableNum,
		config.ToOverlaySubnetTableNum,
		config.OverlayMarkTableNum,
		netlink.FAMILY_V4,
	)
	if err != nil {
		return nil, fmt.Errorf("create ipv4 route manager error: %v", err)
	}

	routeV6Manager, err := route.CreateRouteManager(config.LocalDirectTableNum,
		config.ToOverlaySubnetTableNum,
		config.OverlayMarkTableNum,
		netlink.FAMILY_V6,
	)
	if err != nil {
		return nil, fmt.Errorf("create ipv6 route manager error: %v", err)
	}

	neighV4Manager := neigh.CreateNeighManager(netlink.FAMILY_V4)
	neighV6Manager := neigh.CreateNeighManager(netlink.FAMILY_V6)

	iptablesV4Manager, err := iptables.CreateIPtablesManager(iptables.ProtocolIpv4)
	if err != nil {
		return nil, fmt.Errorf("create ipv4 iptables manager error: %v", err)
	}

	iptablesV6Manager, err := iptables.CreateIPtablesManager(iptables.ProtocolIpv6)
	if err != nil {
		return nil, fmt.Errorf("create ipv6 iptables manager error: %v", err)
	}

	addrV4Manager := addr.CreateAddrManager(netlink.FAMILY_V4, config.NodeName)

	if err := ipInstanceInformer.Informer().GetIndexer().AddIndexers(cache.Indexers{
		ByInstanceIPIndexer: indexByInstanceIP,
	}); err != nil {
		return nil, fmt.Errorf("add indexer to ip instance informer failed: %v", err)
	}

	controller := &Controller{
		subnetLister: subnetInformer.Lister(),
		subnetSynced: subnetInformer.Informer().HasSynced,
		subnetQueue:  workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Subnet"),

		networkLister: networkInformer.Lister(),
		networkSynced: networkInformer.Informer().HasSynced,

		ipInstanceLister:  ipInstanceInformer.Lister(),
		ipInstanceSynced:  ipInstanceInformer.Informer().HasSynced,
		ipInstanceQueue:   workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "IPInstance"),
		ipInstanceIndexer: ipInstanceInformer.Informer().GetIndexer(),

		nodeLister: nodeInformer.Lister(),
		nodeSynced: nodeInformer.Informer().HasSynced,
		nodeQueue:  workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Node"),

		config: config,

		routeV4Manager: routeV4Manager,
		routeV6Manager: routeV6Manager,

		neighV4Manager: neighV4Manager,
		neighV6Manager: neighV6Manager,

		addrV4Manager: addrV4Manager,

		iptablesV4Manager:  iptablesV4Manager,
		iptablesV6Manager:  iptablesV6Manager,
		iptablesSyncCh:     make(chan struct{}, 1),
		iptablesSyncTicker: time.NewTicker(config.IptablesCheckDuration),

		nodeIPCache: NewNodeIPCache(),
	}

	_, err = config.KubeClient.CoreV1().Nodes().Get(context.TODO(), config.NodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get node %s info %v", config.NodeName, err)
	}

	networkInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.enqueueAddOrDeleteNetwork,
		DeleteFunc: controller.enqueueAddOrDeleteNetwork,
		UpdateFunc: controller.enqueueUpdateNetwork,
	})

	subnetInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.enqueueAddOrDeleteSubnet,
		DeleteFunc: controller.enqueueAddOrDeleteSubnet,
		UpdateFunc: controller.enqueueUpdateSubnet,
	})

	ipInstanceInformer.Informer().AddEventHandler(cache.FilteringResourceEventHandler{
		FilterFunc: controller.filterIPInstance,
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc:    controller.enqueueAddOrDeleteIPInstance,
			UpdateFunc: controller.enqueueUpdateIPInstance,
			DeleteFunc: controller.enqueueAddOrDeleteIPInstance,
		},
	})

	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.enqueueAddOrDeleteNode,
		UpdateFunc: controller.enqueueUpdateNode,
		DeleteFunc: controller.enqueueAddOrDeleteNode,
	})

	// clustermesh-related
	if feature.MultiClusterEnabled() {
		remoteSubnetInformer := hybridnetInformerFactory.Networking().V1().RemoteSubnets()
		remoteVtepInformer := hybridnetInformerFactory.Networking().V1().RemoteVteps()

		if err := remoteVtepInformer.Informer().GetIndexer().AddIndexers(cache.Indexers{
			ByEndpointIPIndexer: indexByEndpointIP,
		}); err != nil {
			return nil, fmt.Errorf("add indexer to remote vtep informer failed: %v", err)
		}

		controller.remoteSubnetLister = remoteSubnetInformer.Lister()
		controller.remoteSubnetSynced = remoteSubnetInformer.Informer().HasSynced

		controller.remoteVtepLister = remoteVtepInformer.Lister()
		controller.remoteVtepSynced = remoteVtepInformer.Informer().HasSynced
		controller.remoteVtepIndexer = remoteVtepInformer.Informer().GetIndexer()

		remoteSubnetInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    controller.enqueueAddOrDeleteRemoteSubnet,
			UpdateFunc: controller.enqueueUpdateRemoteSubnet,
			DeleteFunc: controller.enqueueAddOrDeleteRemoteSubnet,
		})

		remoteVtepInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    controller.enqueueAddOrDeleteRemoteVtep,
			UpdateFunc: controller.enqueueUpdateRemoteVtep,
			DeleteFunc: controller.enqueueAddOrDeleteRemoteVtep,
		})
	}

	return controller, nil
}

// Run a Controller
func (c *Controller) Run(stopCh <-chan struct{}) error {
	klog.Info("Started controller")
	c.runHealthyServer()

	defer c.subnetQueue.ShutDown()
	defer c.ipInstanceQueue.ShutDown()
	defer c.nodeQueue.ShutDown()

	synced := []cache.InformerSynced{c.subnetSynced, c.ipInstanceSynced, c.networkSynced, c.nodeSynced}

	if feature.MultiClusterEnabled() {
		synced = append(synced, c.remoteSubnetSynced, c.remoteVtepSynced)
	}

	if ok := cache.WaitForCacheSync(stopCh, synced...); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	go wait.Until(c.runSubnetWorker, time.Second, stopCh)
	go wait.Until(c.runIPInstanceWorker, time.Second, stopCh)
	go wait.Until(c.runNodeWorker, time.Second, stopCh)

	if err := c.handleLocalNetworkDeviceEvent(); err != nil {
		return fmt.Errorf("failed to handle local network device event: %v", err)
	}

	if err := c.handleVxlanInterfaceNeighEvent(); err != nil {
		return fmt.Errorf("failed to handle vxlan interface neigh event: %v", err)
	}

	c.iptablesSyncLoop()

	<-stopCh
	klog.Info("Shutting down controller")

	return nil
}

func (c *Controller) GetIPInstanceLister() networkinglister.IPInstanceLister {
	return c.ipInstanceLister
}

func (c *Controller) GetNetworkLister() networkinglister.NetworkLister {
	return c.networkLister
}

func (c *Controller) GetIPInstanceSynced() cache.InformerSynced {
	return c.ipInstanceSynced
}

// Once node network interface is set from down to up for some reasons, the routes and neigh caches for this interface
// will be cleaned, which should cause unrecoverable problems. Listening "UP" netlink events for interfaces and
// triggering subnet and ip instance reconcile loop will be the best way to recover routes and neigh caches.
//
// Restart of vxlan interface will also trigger subnet and ip instance reconcile loop.
func (c *Controller) handleLocalNetworkDeviceEvent() error {
	hostNetNs, err := netns.Get()
	if err != nil {
		return fmt.Errorf("get root netns failed: %v", err)
	}

	go func() {
		for {
			linkCh := make(chan netlink.LinkUpdate, LinkUpdateChainSize)
			exitCh := make(chan struct{})

			errorCallback := func(err error) {
				klog.Errorf("subscribe netlink link event exit with error: %v", err)
				close(exitCh)
			}

			if err := netlink.LinkSubscribeWithOptions(linkCh, nil, netlink.LinkSubscribeOptions{
				Namespace:     &hostNetNs,
				ErrorCallback: errorCallback,
			}); err != nil {
				klog.Errorf("subscribe link update event failed %v", err)
				time.Sleep(NetlinkSubscribeRetryInterval)
				continue
			}

		linkLoop:
			for {
				select {
				case update := <-linkCh:
					if (update.IfInfomsg.Flags&unix.IFF_UP != 0) &&
						!containernetwork.CheckIfContainerNetworkLink(update.Link.Attrs().Name) {

						// Create event to flush routes and neigh caches.
						c.subnetQueue.Add(ActionReconcileSubnet)
						c.ipInstanceQueue.Add(ActionReconcileIPInstance)
					}
				case <-exitCh:
					break linkLoop
				}
			}
		}
	}()

	go func() {
		for {
			addrCh := make(chan netlink.AddrUpdate, AddrUpdateChainSize)
			exitCh := make(chan struct{})

			errorCallback := func(err error) {
				klog.Errorf("subscribe netlink addr event exit with error: %v", err)
				close(exitCh)
			}

			if err := netlink.AddrSubscribeWithOptions(addrCh, nil, netlink.AddrSubscribeOptions{
				Namespace:     &hostNetNs,
				ErrorCallback: errorCallback,
			}); err != nil {
				klog.Errorf("subscribe address update event failed %v", err)
				time.Sleep(NetlinkSubscribeRetryInterval)
				continue
			}

		addrLoop:
			for {
				select {
				case update := <-addrCh:
					if containernetwork.CheckIPIsGlobalUnicast(update.LinkAddress.IP) {
						// Create event to update node configuration.
						c.nodeQueue.Add(ActionReconcileNode)
					}
				case <-exitCh:
					break addrLoop
				}
			}
		}
	}()

	return nil
}

func (c *Controller) handleVxlanInterfaceNeighEvent() error {

	ipSearch := func(ip net.IP, link netlink.Link) error {
		var vtepMac net.HardwareAddr

		if mac, exist := c.nodeIPCache.SearchIP(ip); exist {
			// find node ip.
			vtepMac = mac
		} else {
			ipInstance, err := c.getIPInstanceByAddress(ip)
			if err != nil {
				return fmt.Errorf("get ip instance by address %v failed: %v", ip.String(), err)
			}

			if ipInstance != nil {
				nodeName := ipInstance.Labels[constants.LabelNode]

				node, err := c.nodeLister.Get(nodeName)
				if err != nil {
					return fmt.Errorf("get node %v failed: %v", nodeName, err)
				}

				vtepMac, err = net.ParseMAC(node.Annotations[constants.AnnotationNodeVtepMac])
				if err != nil {
					return fmt.Errorf("parse vtep mac %v failed: %v",
						node.Annotations[constants.AnnotationNodeVtepMac], err)
				}
			} else if feature.MultiClusterEnabled() {
				// try to find remote vtep according to pod ip
				vtep, err := c.getRemoteVtepByEndpointAddress(ip)
				if err != nil {
					return fmt.Errorf("get remote vtep by address %s failed: %v", ip.String(), err)
				}

				if vtep != nil {
					vtepMac, err = net.ParseMAC(vtep.Spec.VtepMAC)
					if err != nil {
						return fmt.Errorf("parse vtep mac %v failed: %v", vtep.Spec.VtepMAC, err)
					}
				}
			}
		}

		if len(vtepMac) == 0 {
			// if ip not exist, try to clear it's neigh entries
			if err := neigh.ClearStaleNeighEntryByIP(link.Attrs().Index, ip); err != nil {
				return fmt.Errorf("clear stale neigh for link %v and ip %v failed: %v",
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
			return fmt.Errorf("set neigh %v failed: %v", neighEntry.String(), err)
		}

		klog.V(4).Infof("resolve ip %v from user space success, target vtep mac %v", ip.String(), vtepMac.String())

		return nil
	}

	ipSearchExecWrapper := func(ip net.IP, link netlink.Link) {
		if err := ipSearch(ip, link); err != nil {
			klog.Errorf("overlay proxy neigh failed: %v", err)
		}
	}

	hostNetNs, err := netns.Get()
	if err != nil {
		return fmt.Errorf("get root netns failed: %v", err)
	}

	timer := time.NewTicker(c.config.VxlanExpiredNeighCachesClearInterval)
	errorMessageWrapper := initErrorMessageWrapper("handle vxlan interface neigh event failed: ")

	go func() {
		for {
			// Clear stale and failed neigh entries for vxlan interface at the first time.
			// Once neigh subscribe failed (include the goroutine exit), it's most probably because of
			// "No buffer space available" problem, we need to clean expired neigh caches.
			if err := clearVxlanExpiredNeighCaches(); err != nil {
				klog.Errorf("clear vxlan expired neigh caches failed: %v", err)
			}

			neighCh := make(chan netlink.NeighUpdate, NeighUpdateChanSize)
			exitCh := make(chan struct{})

			errorCallback := func(err error) {
				klog.Errorf("subscribe netlink neigh event exit with error: %v", err)
				close(exitCh)
			}

			if err := netlink.NeighSubscribeWithOptions(neighCh, nil, netlink.NeighSubscribeOptions{
				Namespace:     &hostNetNs,
				ErrorCallback: errorCallback,
			}); err != nil {
				klog.Errorf("subscribe neigh update event failed: %v", err)
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
							klog.Errorf(errorMessageWrapper("get link by index %v failed: %v", update.LinkIndex, err))
							continue
						}

						if strings.Contains(link.Attrs().Name, containernetwork.VxlanLinkInfix) {
							go ipSearchExecWrapper(update.IP, link)
						}
					}
				case <-timer.C:
					if err := clearVxlanExpiredNeighCaches(); err != nil {
						klog.Errorf("clear vxlan expired neigh caches failed: %v", err)
					}
				case <-exitCh:
					break neighLoop
				}
			}
		}
	}()

	return nil
}

func (c *Controller) iptablesSyncLoop() {
	iptablesSyncFunc := func() error {
		c.iptablesV4Manager.Reset()
		c.iptablesV6Manager.Reset()

		networkList, err := c.networkLister.List(labels.Everything())
		if err != nil {
			return fmt.Errorf("list network failed: %v", err)
		}

		var overlayExist bool
		for _, network := range networkList {
			if networkingv1.GetNetworkType(network) == networkingv1.NetworkTypeOverlay {
				netID := network.Spec.NetID

				overlayIfName, err := containernetwork.GenerateVxlanNetIfName(c.config.NodeVxlanIfName, netID)
				if err != nil {
					return fmt.Errorf("generate vxlan forward node if name failed: %v", err)
				}

				c.iptablesV4Manager.SetOverlayIfName(overlayIfName)
				c.iptablesV6Manager.SetOverlayIfName(overlayIfName)

				overlayExist = true
				break
			}
		}

		// add local subnets
		if overlayExist {
			// Record node ips.
			nodeList, err := c.nodeLister.List(labels.Everything())
			if err != nil {
				return fmt.Errorf("list node failed: %v", err)
			}

			for _, node := range nodeList {
				// Underlay only environment should node print output

				if node.Annotations[constants.AnnotationNodeVtepMac] == "" ||
					node.Annotations[constants.AnnotationNodeVtepIP] == "" ||
					node.Annotations[constants.AnnotationNodeLocalVxlanIPList] == "" {
					klog.Infof("node %v's vtep information has not been updated", node.Name)
					continue
				}

				nodeLocalVxlanIPStringList := strings.Split(node.Annotations[constants.AnnotationNodeLocalVxlanIPList], ",")
				for _, ipString := range nodeLocalVxlanIPStringList {
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
		}

		ipInstanceList, err := c.ipInstanceLister.List(labels.SelectorFromSet(map[string]string{constants.LabelNode: c.config.NodeName}))
		if err != nil {
			return fmt.Errorf("failed to list pod ip instances of node %v: %v", c.config.NodeName, err)
		}
		for _, ipInstance := range ipInstanceList {
			// skip terminating ip instance
			if ipInstance.DeletionTimestamp != nil {
				continue
			}

			podIP, _, err := net.ParseCIDR(ipInstance.Spec.Address.IP)
			if err != nil {
				return fmt.Errorf("parse pod ip %v error: %v", ipInstance.Spec.Address.IP, err)
			}

			subnet, err := c.subnetLister.Get(ipInstance.Spec.Subnet)
			if err != nil {
				return fmt.Errorf("failed to get subnet for ipinstance %s: %v", ipInstance.Name, err)
			}
			reservedIPs := sets.NewString(subnet.Spec.Range.ReservedIPs...)
			// skip reserved ip instance
			if reservedIPs.Has(podIP.String()) {
				continue
			}

			if podIP.To4() == nil {
				c.iptablesV6Manager.RecordLocalPodIP(podIP)
			} else {
				c.iptablesV4Manager.RecordLocalPodIP(podIP)
			}
		}
		// Record subnet cidr.
		subnetList, err := c.subnetLister.List(labels.Everything())
		if err != nil {
			return fmt.Errorf("list subnet failed: %v", err)
		}

		for _, subnet := range subnetList {
			_, cidr, err := net.ParseCIDR(subnet.Spec.Range.CIDR)
			if err != nil {
				return fmt.Errorf("parse subnet cidr %v failed: %v", subnet.Spec.Range.CIDR, err)
			}

			network, err := c.networkLister.Get(subnet.Spec.Network)
			if err != nil {
				return fmt.Errorf("failed to get network for subnet %v", subnet.Name)
			}

			iptablesManager := c.getIPtablesManager(subnet.Spec.Range.Version)
			// isLocal means whether this node belongs to this network
			isLocal := nodeBelongsToNetwork(c.config.NodeName, network)
			// if network is local vlan, record vlan forward interface names
			if isLocal && networkingv1.GetNetworkType(network) == networkingv1.NetworkTypeUnderlay {
				netID := subnet.Spec.NetID
				if netID == nil {
					netID = network.Spec.NetID
				}

				if vlanForwardIfName, err := containernetwork.GenerateVlanNetIfName(c.config.NodeVlanIfName, netID); err == nil {
					iptablesManager.RecordVlanForwardIfName(vlanForwardIfName)
				} else {
					return fmt.Errorf("failed to generate vlan %d net interface name with node vlan name %s, err: %v", *netID, c.config.NodeVlanIfName, err)
				}
			}
			iptablesManager.RecordSubnet(cidr, networkingv1.GetNetworkType(network) == networkingv1.NetworkTypeOverlay, isLocal)
		}

		if feature.MultiClusterEnabled() {
			// If remote overlay network des not exist, the rcmanager will not fetch
			// RemoteSubnet and RemoteVtep. Thus, existence check is redundant here.

			remoteSubnetList, err := c.remoteSubnetLister.List(labels.Everything())
			if err != nil {
				return fmt.Errorf("list remote network failed: %v", err)
			}

			// Record remote vtep ip.
			vtepList, err := c.remoteVtepLister.List(labels.Everything())
			if err != nil {
				return fmt.Errorf("list remote vtep failed: %v", err)
			}

			for _, vtep := range vtepList {
				if _, exist := vtep.Annotations[constants.AnnotationNodeLocalVxlanIPList]; !exist {
					ip := net.ParseIP(vtep.Spec.VtepIP)
					if ip.To4() != nil {
						// v4 address
						c.iptablesV4Manager.RecordRemoteNodeIP(ip)
					} else {
						// v6 address
						c.iptablesV6Manager.RecordRemoteNodeIP(ip)
					}
					continue
				}

				nodeLocalVxlanIPStringList := strings.Split(vtep.Annotations[constants.AnnotationNodeLocalVxlanIPList], ",")
				for _, ipString := range nodeLocalVxlanIPStringList {
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
			for _, remoteSubnet := range remoteSubnetList {
				_, cidr, err := net.ParseCIDR(remoteSubnet.Spec.Range.CIDR)
				if err != nil {
					return fmt.Errorf("parse remote subnet cidr %v failed: %v", remoteSubnet.Spec.Range.CIDR, err)
				}

				c.getIPtablesManager(remoteSubnet.Spec.Range.Version).
					RecordRemoteSubnet(cidr, networkingv1.GetRemoteSubnetType(remoteSubnet) == networkingv1.NetworkTypeOverlay)
			}
		}

		// Sync rules.
		if err := c.iptablesV4Manager.SyncRules(); err != nil {
			return fmt.Errorf("sync v4 iptables rule failed: %v", err)
		}

		globalDisabled, err := containernetwork.CheckIPv6GlobalDisabled()
		if err != nil {
			return fmt.Errorf("check ipv6 global disabled failed: %v", err)
		}

		if !globalDisabled {
			if err := c.iptablesV6Manager.SyncRules(); err != nil {
				return fmt.Errorf("sync v6 iptables rule failed: %v", err)
			}
		}

		return nil
	}

	go func() {
		for {
			select {
			case <-c.iptablesSyncCh:
				if err := iptablesSyncFunc(); err != nil {
					klog.Errorf("sync iptables rule failed: %v", err)
				}
			case <-c.iptablesSyncTicker.C:
				c.iptablesSyncTrigger()
			}
		}
	}()
}

func (c *Controller) iptablesSyncTrigger() {
	select {
	case c.iptablesSyncCh <- struct{}{}:
	default:
	}
}

func (c *Controller) runHealthyServer() {
	health := healthcheck.NewHandler()

	go func() {
		_ = http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", c.config.BindPort), health)
	}()

	klog.Infof("Listen on port: %d", c.config.BindPort)
}

func isNeighResolving(state int) bool {
	// We need a neigh cache to be STALE if it's not used for a while.
	return (state & netlink.NUD_INCOMPLETE) != 0
}

func indexByInstanceIP(obj interface{}) ([]string, error) {
	instance, ok := obj.(*networkingv1.IPInstance)
	if ok {
		podIP, _, err := net.ParseCIDR(instance.Spec.Address.IP)
		if err != nil {
			return []string{}, fmt.Errorf("parse pod ip %v failed: %v", instance.Spec.Address.IP, err)
		}

		return []string{podIP.String()}, nil
	}
	return []string{}, nil
}

var indexByEndpointIP cache.IndexFunc = func(obj interface{}) ([]string, error) {
	vtep, ok := obj.(*networkingv1.RemoteVtep)
	if ok {
		endpointIPs := vtep.Spec.EndpointIPList
		if len(endpointIPs) > 0 {
			return endpointIPs, nil
		}
	}
	return []string{}, nil
}

func clearVxlanExpiredNeighCaches() error {
	linkList, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list link failed: %v", err)
	}

	for _, link := range linkList {
		if strings.Contains(link.Attrs().Name, containernetwork.VxlanLinkInfix) {
			if err := neigh.ClearStaleAddFailedNeighEntries(link.Attrs().Index, netlink.FAMILY_V4); err != nil {
				return fmt.Errorf("clear v4 expired neigh entries for link %v failed: %v",
					link.Attrs().Name, err)
			}

			ipv6Disabled, err := containernetwork.CheckIPv6Disabled(link.Attrs().Name)
			if err != nil {
				return fmt.Errorf("check ipv6 disables for link %v failed: %v", link.Attrs().Name, err)
			}

			if !ipv6Disabled {
				if err := neigh.ClearStaleAddFailedNeighEntries(link.Attrs().Index, netlink.FAMILY_V6); err != nil {
					return fmt.Errorf("clear v6 expired neigh entries for link %v failed: %v",
						link.Attrs().Name, err)
				}
			}
		}
	}

	return nil
}
