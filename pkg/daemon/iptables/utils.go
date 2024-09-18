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

package iptables

import (
	"bytes"
	"net"
)

// Join all words with spaces, terminate with newline and write to buf.
func writeLine(buf *bytes.Buffer, words ...string) {
	// We avoid strings.Join for performance reasons.
	for i := range words {
		buf.WriteString(words[i])
		if i < len(words)-1 {
			buf.WriteByte(' ')
		} else {
			buf.WriteByte('\n')
		}
	}
}

func generateStringsFromIPNets(ipNets []*net.IPNet) []string {
	var ipNetStrings []string
	for _, cidr := range ipNets {
		ipNetStrings = append(ipNetStrings, cidr.String())
	}
	return ipNetStrings
}

func generateStringsFromIPs(ips []net.IP) []string {
	var ipStrings []string
	for _, ipAddr := range ips {
		ipStrings = append(ipStrings, ipAddr.String())
	}
	return ipStrings
}
