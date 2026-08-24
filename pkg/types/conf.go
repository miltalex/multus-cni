// Copyright (c) 2018 Intel Corporation
// Copyright (c) 2021 Multus Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	cni100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	nadutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"
	"gopkg.in/k8snetworkplumbingwg/multus-cni.v4/pkg/logging"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
)

const (
	defaultCNIDir                 = "/var/lib/cni/multus"
	defaultConfDir                = "/etc/cni/multus/net.d"
	defaultBinDir                 = "/opt/cni/bin"
	defaultReadinessIndicatorFile = ""
	defaultMultusNamespace        = "kube-system"
	defaultNonIsolatedNamespace   = "default"
)

// LoadDelegateNetConfList reads DelegateNetConf from bytes
func LoadDelegateNetConfList(bytes []byte, delegateConf *DelegateNetConf) error {
	logging.Debugf("LoadDelegateNetConfList: %s, %v", string(bytes), delegateConf)

	if err := json.Unmarshal(bytes, &delegateConf.ConfList); err != nil {
		return logging.Errorf("LoadDelegateNetConfList: error unmarshalling delegate conflist: %v", err)
	}

	if delegateConf.ConfList.Plugins == nil {
		return logging.Errorf("LoadDelegateNetConfList: delegate must have the 'type' or 'plugin' field")
	}

	if delegateConf.ConfList.Plugins[0].Type == "" {
		return logging.Errorf("LoadDelegateNetConfList: a plugin delegate must have the 'type' field")
	}
	delegateConf.ConfListPlugin = true
	delegateConf.Name = delegateConf.ConfList.Name
	return nil
}

// ConvertNetworkConfigListToNetConfList converts a libcni.NetworkConfigList to a NetConfList
func ConvertNetworkConfigListToNetConfList(ncList *libcni.NetworkConfigList) (*types.NetConfList, error) {
	// Convert Plugins from []*libcni.PluginConfig to []*types.PluginConf
	var plugins []*types.PluginConf
	for _, plugin := range ncList.Plugins {
		plugins = append(plugins, plugin.Network)
	}

	// Create NetConfList
	netConfList := &types.NetConfList{
		CNIVersion:   ncList.CNIVersion,
		Name:         ncList.Name,
		DisableCheck: ncList.DisableCheck,
		DisableGC:    ncList.DisableGC,
		Plugins:      plugins,
	}

	return netConfList, nil
}

// rawConfListBytes rebuilds the complete conflist JSON from a libcni
// NetworkConfigList without losing any field. It takes the list-level keys
// from the original bytes and rebuilds the "plugins" array from each plugin's
// raw bytes. Per-plugin raw bytes are used (instead of confList.Bytes as a
// whole) because libcni appends plugins loaded from a subdirectory chain into
// confList.Plugins without updating confList.Bytes; relying on confList.Bytes
// alone would drop those appended plugins.
func rawConfListBytes(confList *libcni.NetworkConfigList) ([]byte, error) {
	var rawList map[string]interface{}
	if err := json.Unmarshal(confList.Bytes, &rawList); err != nil {
		return nil, logging.Errorf("rawConfListBytes: failed to unmarshal conflist bytes: %v", err)
	}

	plugins := make([]interface{}, 0, len(confList.Plugins))
	for idx, plugin := range confList.Plugins {
		var rawPlugin map[string]interface{}
		if err := json.Unmarshal(plugin.Bytes, &rawPlugin); err != nil {
			return nil, logging.Errorf("rawConfListBytes: failed to unmarshal plugin #%d: %v", idx, err)
		}
		plugins = append(plugins, rawPlugin)
	}
	rawList["plugins"] = plugins

	return json.Marshal(rawList)
}

// mergeConfListBytes preserves runtime fields injected into the legacy Bytes
// after CNINetworkConfigList was built. Other fields must continue to come
// from the lossless configuration.
func mergeConfListBytes(losslessBytes, housekeepingBytes []byte) ([]byte, error) {
	if len(housekeepingBytes) == 0 {
		return losslessBytes, nil
	}

	var lossless, housekeeping map[string]json.RawMessage
	if err := json.Unmarshal(losslessBytes, &lossless); err != nil {
		return nil, logging.Errorf("mergeConfListBytes: failed to unmarshal lossless bytes: %v", err)
	}
	if err := json.Unmarshal(housekeepingBytes, &housekeeping); err != nil {
		return nil, logging.Errorf("mergeConfListBytes: failed to unmarshal housekeeping bytes: %v", err)
	}

	var losslessPlugins, housekeepingPlugins []json.RawMessage
	if err := json.Unmarshal(lossless["plugins"], &losslessPlugins); err != nil {
		return nil, logging.Errorf("mergeConfListBytes: failed to unmarshal lossless plugins: %v", err)
	}
	if err := json.Unmarshal(housekeeping["plugins"], &housekeepingPlugins); err != nil {
		return nil, logging.Errorf("mergeConfListBytes: failed to unmarshal housekeeping plugins: %v", err)
	}
	if len(losslessPlugins) != len(housekeepingPlugins) {
		return nil, logging.Errorf("mergeConfListBytes: plugin count differs between legacy and housekeeping bytes: %d != %d", len(losslessPlugins), len(housekeepingPlugins))
	}

	for idx := range losslessPlugins {
		var losslessPlugin, housekeepingPlugin map[string]json.RawMessage
		if err := json.Unmarshal(losslessPlugins[idx], &losslessPlugin); err != nil {
			return nil, logging.Errorf("mergeConfListBytes: failed to unmarshal lossless plugin #%d: %v", idx, err)
		}
		if err := json.Unmarshal(housekeepingPlugins[idx], &housekeepingPlugin); err != nil {
			return nil, logging.Errorf("mergeConfListBytes: failed to unmarshal housekeeping plugin #%d: %v", idx, err)
		}
		for _, key := range []string{"deviceID", "pciBusID"} {
			if value, ok := housekeepingPlugin[key]; ok {
				losslessPlugin[key] = value
			}
		}
		if housekeepingArgs, ok := housekeepingPlugin["args"]; ok {
			args, err := mergeCNIArgs(losslessPlugin["args"], housekeepingArgs)
			if err != nil {
				return nil, logging.Errorf("mergeConfListBytes: failed to merge plugin #%d args: %v", idx, err)
			}
			losslessPlugin["args"] = args
		}
		pluginBytes, err := json.Marshal(losslessPlugin)
		if err != nil {
			return nil, logging.Errorf("mergeConfListBytes: failed to marshal plugin #%d: %v", idx, err)
		}
		losslessPlugins[idx] = pluginBytes
	}

	pluginsBytes, err := json.Marshal(losslessPlugins)
	if err != nil {
		return nil, logging.Errorf("mergeConfListBytes: failed to marshal plugins: %v", err)
	}
	lossless["plugins"] = pluginsBytes
	return json.Marshal(lossless)
}

func mergeCNIArgs(losslessBytes, housekeepingBytes json.RawMessage) ([]byte, error) {
	var lossless, housekeeping map[string]json.RawMessage
	if len(losslessBytes) != 0 {
		if err := json.Unmarshal(losslessBytes, &lossless); err != nil {
			return nil, logging.Errorf("mergeCNIArgs: failed to unmarshal lossless args: %v", err)
		}
	} else {
		lossless = map[string]json.RawMessage{}
	}
	if err := json.Unmarshal(housekeepingBytes, &housekeeping); err != nil {
		return nil, logging.Errorf("mergeCNIArgs: failed to unmarshal housekeeping args: %v", err)
	}

	housekeepingCNI, ok := housekeeping["cni"]
	if !ok {
		return json.Marshal(lossless)
	}
	var losslessCNI, housekeepingCNIMap map[string]json.RawMessage
	if losslessCNIBytes, ok := lossless["cni"]; ok {
		if err := json.Unmarshal(losslessCNIBytes, &losslessCNI); err != nil {
			return nil, logging.Errorf("mergeCNIArgs: failed to unmarshal lossless cni args: %v", err)
		}
	} else {
		losslessCNI = map[string]json.RawMessage{}
	}
	if err := json.Unmarshal(housekeepingCNI, &housekeepingCNIMap); err != nil {
		return nil, logging.Errorf("mergeCNIArgs: failed to unmarshal housekeeping cni args: %v", err)
	}
	for key, value := range housekeepingCNIMap {
		losslessCNI[key] = value
	}
	cniBytes, err := json.Marshal(losslessCNI)
	if err != nil {
		return nil, logging.Errorf("mergeCNIArgs: failed to marshal cni args: %v", err)
	}
	lossless["cni"] = cniBytes
	return json.Marshal(lossless)
}

// UnmarshalJSON restores delegate Bytes from the pre-#1521 scratch-cache
// representation. Those caches include CNINetworkConfigList with lossless raw
// plugin bytes, while Bytes was marshaled from the lossy NetConfList. The
// legacy field is used only while decoding; Bytes remains the sole source of
// truth after the delegate is loaded.
func (delegateConf *DelegateNetConf) UnmarshalJSON(data []byte) error {
	type delegateNetConf DelegateNetConf
	legacy := struct {
		*delegateNetConf
		CNINetworkConfigList *libcni.NetworkConfigList `json:"CNINetworkConfigList"`
	}{
		delegateNetConf: (*delegateNetConf)(delegateConf),
	}

	if err := json.Unmarshal(data, &legacy); err != nil {
		return logging.Errorf("DelegateNetConf: error unmarshalling delegate config: %v", err)
	}

	// Direct-plugin delegates in old caches also carried this field, but it was
	// empty because only conflist delegates populated CNINetworkConfigList.
	if legacy.CNINetworkConfigList == nil ||
		(len(legacy.CNINetworkConfigList.Bytes) == 0 && len(legacy.CNINetworkConfigList.Plugins) == 0) {
		return nil
	}

	bytes, err := rawConfListBytes(legacy.CNINetworkConfigList)
	if err != nil {
		return logging.Errorf("DelegateNetConf: failed to restore Bytes from legacy CNINetworkConfigList: %v", err)
	}
	bytes, err = mergeConfListBytes(bytes, delegateConf.Bytes)
	if err != nil {
		return logging.Errorf("DelegateNetConf: failed to merge legacy CNINetworkConfigList with Bytes: %v", err)
	}
	delegateConf.Bytes = bytes
	return nil
}

// InjectCNIVersionInConfList sets the cniVersion field on a conflist JSON
// without losing any other field. It is used on the DEL path to backfill the
// cniVersion onto the raw bytes; marshaling the structured NetConfList instead
// would strip CNI-specific fields and break the plugin's DEL.
func InjectCNIVersionInConfList(inBytes []byte, cniVersion string) ([]byte, error) {
	var rawConfig map[string]interface{}
	if err := json.Unmarshal(inBytes, &rawConfig); err != nil {
		return nil, logging.Errorf("InjectCNIVersionInConfList: failed to unmarshal inBytes: %v", err)
	}
	rawConfig["cniVersion"] = cniVersion
	return json.Marshal(rawConfig)
}

// LoadDelegateNetConfFromConfList converts a libcni.NetworkConfigList into a DelegateNetConf structure
func LoadDelegateNetConfFromConfList(confList *libcni.NetworkConfigList, netElement *NetworkSelectionElement, deviceID string, resourceName string) (*DelegateNetConf, error) {
	var err error
	logging.Debugf("LoadDelegateNetConfFromConfList: %v, %v, %s", confList, netElement, deviceID)

	// Convert libcni.NetworkConfigList to NetConfList
	netConfList, err := ConvertNetworkConfigListToNetConfList(confList)
	if err != nil {
		return nil, err
	}

	delegateConf := &DelegateNetConf{
		Name:           netConfList.Name,
		ConfList:       *netConfList,
		ConfListPlugin: true,
	}

	// Preserve the original conflist bytes losslessly. The structured
	// NetConfList (via cnitypes.PluginConf) drops any field outside
	// cniVersion/name/type/capabilities/ipam.type/dns, which would strip
	// CNI-specific fields such as calico's kubeconfig/datastore_type and
	// break the plugin's DEL (e.g. failing to release IPs). Rebuild from the
	// libcni raw bytes instead so DEL receives the same complete config ADD did.
	pluginsBytes, err := rawConfListBytes(confList)
	if err != nil {
		return nil, logging.Errorf("LoadDelegateNetConfFromConfList: error rebuilding conflist bytes: %v", err)
	}

	if deviceID != "" {
		pluginsBytes, err = addDeviceIDInConfList(pluginsBytes, deviceID)
		if err != nil {
			return nil, logging.Errorf("LoadDelegateNetConfFromConfList: failed to add deviceID in NetConfList bytes: %v", err)
		}
		delegateConf.ResourceName = resourceName
		delegateConf.DeviceID = deviceID
	}

	if netElement != nil && netElement.CNIArgs != nil {
		pluginsBytes, err = addCNIArgsInConfList(pluginsBytes, netElement.CNIArgs)
		if err != nil {
			return nil, logging.Errorf("LoadDelegateNetConfFromConfList: failed to add cni-args in NetConfList bytes: %v", err)
		}
	}

	delegateConf.Bytes = pluginsBytes

	if netElement != nil {
		if netElement.Name != "" {
			// Overwrite CNI config name with net-attach-def name
			delegateConf.Name = fmt.Sprintf("%s/%s", netElement.Namespace, netElement.Name)
		}
		if netElement.InterfaceRequest != "" {
			delegateConf.IfnameRequest = netElement.InterfaceRequest
		}
		if netElement.MacRequest != "" {
			delegateConf.MacRequest = netElement.MacRequest
		}
		if netElement.IPRequest != nil {
			delegateConf.IPRequest = netElement.IPRequest
		}
		if netElement.BandwidthRequest != nil {
			delegateConf.BandwidthRequest = netElement.BandwidthRequest
		}
		if netElement.PortMappingsRequest != nil {
			delegateConf.PortMappingsRequest = netElement.PortMappingsRequest
		}
		if netElement.GatewayRequest != nil {
			var list []net.IP
			if delegateConf.GatewayRequest != nil {
				list = append(*delegateConf.GatewayRequest, *netElement.GatewayRequest...)
			} else {
				list = *netElement.GatewayRequest
			}
			delegateConf.GatewayRequest = &list
		}
		if netElement.InfinibandGUIDRequest != "" {
			delegateConf.InfinibandGUIDRequest = netElement.InfinibandGUIDRequest
		}
		if netElement.DeviceID != "" {
			if deviceID != "" {
				logging.Debugf("Warning: Both RuntimeConfig and ResourceMap provide deviceID. Ignoring RuntimeConfig")
			} else {
				delegateConf.DeviceID = netElement.DeviceID
			}
		}
	}

	return delegateConf, nil
}

// LoadDelegateNetConf converts raw CNI JSON into a DelegateNetConf structure
func LoadDelegateNetConf(bytes []byte, netElement *NetworkSelectionElement, deviceID string, resourceName string) (*DelegateNetConf, error) {
	var err error
	logging.Debugf("LoadDelegateNetConf: %s, %v, %s", string(bytes), netElement, deviceID)

	delegateConf := &DelegateNetConf{}
	if err := json.Unmarshal(bytes, &delegateConf.Conf); err != nil {
		return nil, logging.Errorf("LoadDelegateNetConf: error unmarshalling delegate config: %v", err)
	}
	delegateConf.Name = delegateConf.Conf.Name

	// Do some minimal validation
	if delegateConf.Conf.Type == "" {
		if err := LoadDelegateNetConfList(bytes, delegateConf); err != nil {
			return nil, logging.Errorf("LoadDelegateNetConf: failed with: %v", err)
		}
		if deviceID != "" {
			bytes, err = addDeviceIDInConfList(bytes, deviceID)
			if err != nil {
				return nil, logging.Errorf("LoadDelegateNetConf: failed to add deviceID in NetConfList bytes: %v", err)
			}
			delegateConf.ResourceName = resourceName
			delegateConf.DeviceID = deviceID
		}
		if netElement != nil && netElement.CNIArgs != nil {
			bytes, err = addCNIArgsInConfList(bytes, netElement.CNIArgs)
			if err != nil {
				return nil, logging.Errorf("LoadDelegateNetConf(): failed to add cni-args in NetConfList bytes: %v", err)
			}
		}
	} else {
		if deviceID != "" {
			bytes, err = delegateAddDeviceID(bytes, deviceID)
			if err != nil {
				return nil, logging.Errorf("LoadDelegateNetConf: failed to add deviceID in NetConf bytes: %v", err)
			}
			// Save them for housekeeping
			delegateConf.ResourceName = resourceName
			delegateConf.DeviceID = deviceID
		}
		if netElement != nil && netElement.CNIArgs != nil {
			bytes, err = addCNIArgsInConfig(bytes, netElement.CNIArgs)
			if err != nil {
				return nil, logging.Errorf("LoadDelegateNetConf(): failed to add cni-args in NetConfList bytes: %v", err)
			}
		}
	}

	if netElement != nil {
		if netElement.Name != "" {
			// Overwrite CNI config name with net-attach-def name
			delegateConf.Name = fmt.Sprintf("%s/%s", netElement.Namespace, netElement.Name)
		}
		if netElement.InterfaceRequest != "" {
			delegateConf.IfnameRequest = netElement.InterfaceRequest
		}
		if netElement.MacRequest != "" {
			delegateConf.MacRequest = netElement.MacRequest
		}
		if netElement.IPRequest != nil {
			delegateConf.IPRequest = netElement.IPRequest
		}
		if netElement.BandwidthRequest != nil {
			delegateConf.BandwidthRequest = netElement.BandwidthRequest
		}
		if netElement.PortMappingsRequest != nil {
			delegateConf.PortMappingsRequest = netElement.PortMappingsRequest
		}
		if netElement.GatewayRequest != nil {
			var list []net.IP
			if delegateConf.GatewayRequest != nil {
				list = append(*delegateConf.GatewayRequest, *netElement.GatewayRequest...)
			} else {
				list = *netElement.GatewayRequest
			}
			delegateConf.GatewayRequest = &list
		}
		if netElement.InfinibandGUIDRequest != "" {
			delegateConf.InfinibandGUIDRequest = netElement.InfinibandGUIDRequest
		}
		if netElement.DeviceID != "" {
			if deviceID != "" {
				logging.Debugf("Warning: Both RuntimeConfig and ResourceMap provide deviceID. Ignoring RuntimeConfig")
			} else {
				delegateConf.DeviceID = netElement.DeviceID
			}
		}
	}

	delegateConf.Bytes = bytes

	return delegateConf, nil
}

// mergeCNIRuntimeConfig creates CNI runtimeconfig from delegate
func mergeCNIRuntimeConfig(runtimeConfig *RuntimeConfig, delegate *DelegateNetConf) *RuntimeConfig {
	logging.Debugf("mergeCNIRuntimeConfig: %v %v", runtimeConfig, delegate)
	var mergedRuntimeConfig RuntimeConfig

	if runtimeConfig == nil {
		mergedRuntimeConfig = RuntimeConfig{}
	} else {
		mergedRuntimeConfig = *runtimeConfig
	}

	// multus inject RuntimeConfig only in case of non MasterPlugin.
	if delegate.MasterPlugin != true {
		logging.Debugf("mergeCNIRuntimeConfig: add runtimeConfig for net-attach-def: %v", mergedRuntimeConfig)
		if delegate.PortMappingsRequest != nil {
			mergedRuntimeConfig.PortMaps = delegate.PortMappingsRequest
		}
		if delegate.BandwidthRequest != nil {
			mergedRuntimeConfig.Bandwidth = delegate.BandwidthRequest
		}
		if delegate.IPRequest != nil {
			mergedRuntimeConfig.IPs = delegate.IPRequest
		}
		if delegate.MacRequest != "" {
			mergedRuntimeConfig.Mac = delegate.MacRequest
		}
		if delegate.InfinibandGUIDRequest != "" {
			mergedRuntimeConfig.InfinibandGUID = delegate.InfinibandGUIDRequest
		}
		if delegate.DeviceID != "" {
			mergedRuntimeConfig.DeviceID = delegate.DeviceID
		}
		logging.Debugf("mergeCNIRuntimeConfig: add runtimeConfig for net-attach-def: %v", mergedRuntimeConfig)
	}
	return &mergedRuntimeConfig
}

// CreateCNIRuntimeConf create CNI RuntimeConf for a delegate. If delegate configuration
// exists, merge data with the runtime config.
func CreateCNIRuntimeConf(args *skel.CmdArgs, k8sArgs *K8sArgs, ifName string, rc *RuntimeConfig, delegate *DelegateNetConf) (*libcni.RuntimeConf, string) {
	podName := string(k8sArgs.K8S_POD_NAME)
	podNamespace := string(k8sArgs.K8S_POD_NAMESPACE)
	podUID := string(k8sArgs.K8S_POD_UID)
	sandboxID := string(k8sArgs.K8S_POD_INFRA_CONTAINER_ID)
	return newCNIRuntimeConf(args.ContainerID, sandboxID, podName, podNamespace, podUID, args.Netns, ifName, rc, delegate)
}

// newCNIRuntimeConf creates the CNI `RuntimeConf` for the given ADD / DEL request.
func newCNIRuntimeConf(containerID, sandboxID, podName, podNamespace, podUID, netNs, ifName string, rc *RuntimeConfig, delegate *DelegateNetConf) (*libcni.RuntimeConf, string) {
	logging.Debugf("LoadCNIRuntimeConf: %s, %v %v", ifName, rc, delegate)

	delegateRc := delegateRuntimeConfig(containerID, delegate, rc, ifName)
	// In part, adapted from K8s pkg/kubelet/dockershim/network/cni/cni.go#buildCNIRuntimeConf
	rt := createRuntimeConf(netNs, podNamespace, podName, containerID, sandboxID, podUID, ifName)

	var cniDeviceInfoFile string

	// Populate rt.Args with CNI_ARGS if the rt.Args value is not set
	cniArgs := os.Getenv("CNI_ARGS")
	if cniArgs != "" {
		logging.Debugf("ARGS: %s", cniArgs)
		for _, arg := range strings.Split(cniArgs, ";") {
			// SplitN to handle = within values, like BLAH=foo=bar
			keyval := strings.SplitN(arg, "=", 2)
			if len(keyval) != 2 {
				logging.Errorf("CreateCNIRuntimeConf: CNI_ARGS %s %s %d is not recognized as CNI arg, skipped", arg, keyval, len(keyval))
				continue
			}

			envKey := string(keyval[0])
			envVal := string(keyval[1])
			found := false
			for i := range rt.Args {
				// Update existing key if its value is empty
				if rt.Args[i][0] == envKey && rt.Args[i][1] == "" && envVal != "" {
					logging.Debugf("CreateCNIRuntimeConf: add new val: %s", arg)
					rt.Args[i][1] = envVal
					found = true
					break
				}
			}
			if !found {
				// Add the new key if it didn't exist yet
				rt.Args = append(rt.Args, [2]string{envKey, envVal})
			}
		}
	}

	if delegateRc != nil {
		cniDeviceInfoFile = delegateRc.CNIDeviceInfoFile
		capabilityArgs := map[string]interface{}{}
		if len(delegateRc.PortMaps) != 0 {
			capabilityArgs["portMappings"] = delegateRc.PortMaps
		}
		if delegateRc.Bandwidth != nil {
			capabilityArgs["bandwidth"] = delegateRc.Bandwidth
		}
		if len(delegateRc.IPs) != 0 {
			capabilityArgs["ips"] = delegateRc.IPs
		}
		if len(delegateRc.Mac) != 0 {
			capabilityArgs["mac"] = delegateRc.Mac
		}
		if len(delegateRc.InfinibandGUID) != 0 {
			capabilityArgs["infinibandGUID"] = delegateRc.InfinibandGUID
		}
		if delegateRc.DeviceID != "" {
			capabilityArgs["deviceID"] = delegateRc.DeviceID
		}
		if delegateRc.CNIDeviceInfoFile != "" {
			capabilityArgs["CNIDeviceInfoFile"] = delegateRc.CNIDeviceInfoFile
		}
		rt.CapabilityArgs = capabilityArgs
	}
	return rt, cniDeviceInfoFile
}

// createRuntimeConf creates the CNI `RuntimeConf` for the given ADD / DEL request.
func createRuntimeConf(netNs, podNamespace, podName, containerID, sandboxID, podUID, ifName string) *libcni.RuntimeConf {
	return &libcni.RuntimeConf{
		ContainerID: containerID,
		NetNS:       netNs,
		IfName:      ifName,
		// NOTE: Verbose logging depends on this order, so please keep Args order.
		Args: [][2]string{
			{"IgnoreUnknown", "true"},
			{"K8S_POD_NAMESPACE", podNamespace},
			{"K8S_POD_NAME", podName},
			{"K8S_POD_INFRA_CONTAINER_ID", sandboxID},
			{"K8S_POD_UID", podUID},
		},
	}
}

// delegateRuntimeConfig creates the CNI `RuntimeConf` for the given ADD / DEL request.
func delegateRuntimeConfig(containerID string, delegate *DelegateNetConf, rc *RuntimeConfig, ifName string) *RuntimeConfig {
	var delegateRc *RuntimeConfig

	if delegate != nil {
		delegateRc = mergeCNIRuntimeConfig(rc, delegate)
		if delegateRc.DeviceID != "" {
			if delegateRc.CNIDeviceInfoFile != "" {
				logging.Debugf("Warning: Existing value of CNIDeviceInfoFile will be overwritten %s", delegateRc.CNIDeviceInfoFile)
			}
			autoDeviceInfo := fmt.Sprintf("%s-%s_%s", delegate.Name, containerID, ifName)
			delegateRc.CNIDeviceInfoFile = nadutils.GetCNIDeviceInfoPath(autoDeviceInfo)
			logging.Debugf("Adding auto-generated CNIDeviceInfoFile: %s", delegateRc.CNIDeviceInfoFile)
		}
	} else {
		delegateRc = rc
	}
	return delegateRc
}

// GetGatewayFromResult retrieves gateway IP addresses from CNI result
func GetGatewayFromResult(result *cni100.Result) []net.IP {
	var gateways []net.IP

	for _, route := range result.Routes {
		if mask, _ := route.Dst.Mask.Size(); mask == 0 {
			gateways = append(gateways, route.GW)
		}
	}
	return gateways
}

// GetDefaultNetConf returns NetConf with default variables
func GetDefaultNetConf() *NetConf {
	// LogToStderr's default value set to true
	return &NetConf{
		BinDir:                 defaultBinDir,
		ConfDir:                defaultConfDir,
		CNIDir:                 defaultCNIDir,
		LogToStderr:            true,
		MultusNamespace:        defaultMultusNamespace,
		NonIsolatedNamespaces:  []string{defaultNonIsolatedNamespace},
		ReadinessIndicatorFile: defaultReadinessIndicatorFile,
		SystemNamespaces:       []string{"kube-system"},
	}

}

// LoadNetConf converts inputs (i.e. stdin) to NetConf
func LoadNetConf(bytes []byte) (*NetConf, error) {
	netconf := GetDefaultNetConf()

	logging.Debugf("LoadNetConf: %s", string(bytes))
	if err := json.Unmarshal(bytes, netconf); err != nil {
		return nil, logging.Errorf("LoadNetConf: failed to load netconf: %v", err)
	}

	// Logging
	logging.SetLogStderr(netconf.LogToStderr)
	logging.SetLogOptions(netconf.LogOptions)
	if netconf.LogFile != "" {
		logging.SetLogFile(netconf.LogFile)
	}
	if netconf.LogLevel != "" {
		logging.SetLogLevel(netconf.LogLevel)
	}

	// Parse previous result
	if netconf.RawPrevResult != nil {
		resultBytes, err := json.Marshal(netconf.RawPrevResult)
		if err != nil {
			return nil, logging.Errorf("LoadNetConf: could not serialize prevResult: %v", err)
		}
		res, err := version.NewResult(netconf.CNIVersion, resultBytes)
		if err != nil {
			return nil, logging.Errorf("LoadNetConf: could not parse prevResult: %v", err)
		}
		netconf.RawPrevResult = nil
		netconf.PrevResult, err = cni100.NewResultFromResult(res)
		if err != nil {
			return nil, logging.Errorf("LoadNetConf: could not convert result to current version: %v", err)
		}
	}

	// Delegates must always be set. If no kubeconfig is present, the
	// delegates are executed in-order.  If a kubeconfig is present,
	// at least one delegate must be present and the first delegate is
	// the master plugin. Kubernetes CRD delegates are then appended to
	// the existing delegate list and all delegates executed in-order.

	if len(netconf.RawDelegates) == 0 && netconf.ClusterNetwork == "" {
		return nil, logging.Errorf("LoadNetConf: at least one delegate/clusterNetwork must be specified")
	}

	// setup namespace isolation
	if netconf.RawNonIsolatedNamespaces != "" {
		// Parse the comma separated list
		nonisolated := strings.Split(netconf.RawNonIsolatedNamespaces, ",")
		// Cleanup the whitespace
		for i, nonv := range nonisolated {
			nonisolated[i] = strings.TrimSpace(nonv)
		}
		netconf.NonIsolatedNamespaces = nonisolated
	}

	// get RawDelegates and put delegates field
	if netconf.ClusterNetwork == "" {
		// for Delegates
		if len(netconf.RawDelegates) == 0 {
			return nil, logging.Errorf("LoadNetConf: at least one delegate must be specified")
		}
		for idx, rawConf := range netconf.RawDelegates {
			bytes, err := json.Marshal(rawConf)
			if err != nil {
				return nil, logging.Errorf("LoadNetConf: error marshalling delegate %d config: %v", idx, err)
			}
			delegateConf, err := LoadDelegateNetConf(bytes, nil, "", "")
			if err != nil {
				return nil, logging.Errorf("LoadNetConf: failed to load delegate %d config: %v", idx, err)
			}
			netconf.Delegates = append(netconf.Delegates, delegateConf)
		}
		netconf.RawDelegates = nil

		// First delegate is always the master plugin
		netconf.Delegates[0].MasterPlugin = true
	}

	return netconf, nil
}

// AddDelegates appends the new delegates to the delegates list
func (n *NetConf) AddDelegates(newDelegates []*DelegateNetConf) error {
	logging.Debugf("AddDelegates: %v", newDelegates)
	n.Delegates = append(n.Delegates, newDelegates...)
	return nil
}

// delegateAddDeviceID injects deviceID information in delegate bytes
func delegateAddDeviceID(inBytes []byte, deviceID string) ([]byte, error) {
	var rawConfig map[string]interface{}
	var err error

	err = json.Unmarshal(inBytes, &rawConfig)
	if err != nil {
		return nil, logging.Errorf("delegateAddDeviceID: failed to unmarshal inBytes: %v", err)
	}
	// Inject deviceID
	rawConfig["deviceID"] = deviceID
	rawConfig["pciBusID"] = deviceID
	configBytes, err := json.Marshal(rawConfig)
	if err != nil {
		return nil, logging.Errorf("delegateAddDeviceID: failed to re-marshal Spec.Config: %v", err)
	}
	logging.Debugf("delegateAddDeviceID updated configBytes %s", string(configBytes))
	return configBytes, nil
}

// addDeviceIDInConfList injects deviceID information in delegate bytes
func addDeviceIDInConfList(inBytes []byte, deviceID string) ([]byte, error) {
	var rawConfig map[string]interface{}
	var err error

	err = json.Unmarshal(inBytes, &rawConfig)
	if err != nil {
		return nil, logging.Errorf("addDeviceIDInConfList: failed to unmarshal inBytes: %v", err)
	}

	pList, ok := rawConfig["plugins"]
	if !ok {
		return nil, logging.Errorf("addDeviceIDInConfList: unable to get plugin list")
	}

	pMap, ok := pList.([]interface{})
	if !ok {
		return nil, logging.Errorf("addDeviceIDInConfList: unable to typecast plugin list")
	}

	for idx, plugin := range pMap {
		currentPlugin, ok := plugin.(map[string]interface{})
		if !ok {
			return nil, logging.Errorf("addDeviceIDInConfList: unable to typecast plugin #%d", idx)
		}
		// Inject deviceID
		currentPlugin["deviceID"] = deviceID
		currentPlugin["pciBusID"] = deviceID
	}

	configBytes, err := json.Marshal(rawConfig)
	if err != nil {
		return nil, logging.Errorf("addDeviceIDInConfList: failed to re-marshal: %v", err)
	}
	logging.Debugf("addDeviceIDInConfList: updated configBytes %s", string(configBytes))
	return configBytes, nil
}

// injectCNIArgs injects given args to cniConfig
func injectCNIArgs(cniConfig *map[string]interface{}, args *map[string]interface{}) error {
	if argsval, ok := (*cniConfig)["args"]; ok {
		argsvalmap := argsval.(map[string]interface{})
		if cnival, ok := argsvalmap["cni"]; ok {
			cnivalmap := cnival.(map[string]interface{})
			// merge it if conf has args
			for key, val := range *args {
				cnivalmap[key] = val
			}
		} else {
			argsvalmap["cni"] = *args
		}
	} else {
		argsval := map[string]interface{}{}
		argsval["cni"] = *args
		(*cniConfig)["args"] = argsval
	}
	return nil
}

// addCNIArgsInConfig injects given cniArgs to CNI config in inBytes
func addCNIArgsInConfig(inBytes []byte, cniArgs *map[string]interface{}) ([]byte, error) {
	var rawConfig map[string]interface{}
	var err error

	err = json.Unmarshal(inBytes, &rawConfig)
	if err != nil {
		return nil, logging.Errorf("addCNIArgsInConfig(): failed to unmarshal inBytes: %v", err)
	}

	injectCNIArgs(&rawConfig, cniArgs)

	configBytes, err := json.Marshal(rawConfig)
	if err != nil {
		return nil, logging.Errorf("addCNIArgsInConfig(): failed to re-marshal: %v", err)
	}
	return configBytes, nil
}

// addCNIArgsInConfList injects given cniArgs to CNI conflist in inBytes
func addCNIArgsInConfList(inBytes []byte, cniArgs *map[string]interface{}) ([]byte, error) {
	var rawConfig map[string]interface{}
	var err error

	err = json.Unmarshal(inBytes, &rawConfig)
	if err != nil {
		return nil, logging.Errorf("addCNIArgsInConfList(): failed to unmarshal inBytes: %v", err)
	}

	pList, ok := rawConfig["plugins"]
	if !ok {
		return nil, logging.Errorf("addCNIArgsInConfList(): unable to get plugin list")
	}

	pMap, ok := pList.([]interface{})
	if !ok {
		return nil, logging.Errorf("addCNIArgsInConfList(): unable to typecast plugin list")
	}

	for idx := range pMap {
		valMap := pMap[idx].(map[string]interface{})
		injectCNIArgs(&valMap, cniArgs)
	}

	configBytes, err := json.Marshal(rawConfig)
	if err != nil {
		return nil, logging.Errorf("addCNIArgsInConfList(): failed to re-marshal: %v", err)
	}
	return configBytes, nil
}

// CheckGatewayConfig check gatewayRequest and mark IsFilter{V4,V6}Gateway flag if
// gw filtering is required
func CheckGatewayConfig(delegates []*DelegateNetConf) error {

	v4Gateways := 0
	v6Gateways := 0

	// Check the gateway
	for _, delegate := range delegates {
		if delegate.GatewayRequest != nil {
			for _, gw := range *delegate.GatewayRequest {
				if gw.To4() != nil {
					v4Gateways++
				} else {
					v6Gateways++
				}
			}
		}
	}

	if v4Gateways > 1 || v6Gateways > 1 {
		return fmt.Errorf("multus does not support ECMP for default-route")
	}

	// set filter flag for each delegate
	for i, delegate := range delegates {
		delegates[i].IsFilterV4Gateway = true
		delegates[i].IsFilterV6Gateway = true
		if delegate.GatewayRequest != nil {
			for _, gw := range *delegate.GatewayRequest {
				if gw.To4() != nil {
					delegates[i].IsFilterV4Gateway = false
				} else {
					delegates[i].IsFilterV6Gateway = false
				}
			}
		}
	}
	return nil
}

// CheckSystemNamespaces checks whether given namespace is in systemNamespaces or not.
func CheckSystemNamespaces(namespace string, systemNamespaces []string) bool {
	for _, nsname := range systemNamespaces {
		if namespace == nsname {
			return true
		}
	}
	return false
}

// GetReadinessIndicatorFile waits for readinessIndicatorFile
func GetReadinessIndicatorFile(readinessIndicatorFileRaw string) error {
	cleanpath := filepath.Clean(readinessIndicatorFileRaw)
	readinessIndicatorFile, err := filepath.Abs(cleanpath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path of readinessIndicatorFile: %v", err)
	}

	pollDuration := 1000 * time.Millisecond
	pollTimeout := 45 * time.Second
	return utilwait.PollImmediate(pollDuration, pollTimeout, func() (bool, error) {
		_, err := os.Stat(readinessIndicatorFile)
		return err == nil, nil
	})
}

// ReadinessIndicatorExistsNow reports if the readiness indicator exists immediately.
func ReadinessIndicatorExistsNow(readinessIndicatorFileRaw string) (bool, error) {
	cleanpath := filepath.Clean(readinessIndicatorFileRaw)
	readinessIndicatorFile, err := filepath.Abs(cleanpath)
	if err != nil {
		return false, fmt.Errorf("failed to get absolute path of readinessIndicatorFile: %v", err)
	}

	_, err = os.Stat(readinessIndicatorFile)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
