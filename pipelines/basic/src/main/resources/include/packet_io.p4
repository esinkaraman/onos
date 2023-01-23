/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __PACKET_IO__
#define __PACKET_IO__

#include "headers.p4"
#include "defines.p4"

control packetio_ingress(inout headers_t hdr,
                         inout standard_metadata_t standard_metadata) {


    apply {
        if (standard_metadata.ingress_port == CPU_PORT) {
            standard_metadata.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
            exit;
        }
    }
}

control packetio_egress(inout headers_t hdr,
			inout local_metadata_t local_metadata,
                        inout standard_metadata_t standard_metadata) {
    apply {
        if (standard_metadata.egress_port == CPU_PORT) {
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = standard_metadata.ingress_port;
        }
	if (local_metadata.report == _TRUE) {
           hdr.ids.reg_index = 	local_metadata.reg_index;
	   hdr.ids.r1 = local_metadata.r1;
	   hdr.ids.r2 = local_metadata.r2;
	   hdr.ids.r3 = local_metadata.r3;
	   hdr.ids.r4 = local_metadata.r4;
	   hdr.ids.r5 = local_metadata.r5;
	   hdr.ids.r6 = local_metadata.r6;
	   hdr.ids.r7 = local_metadata.r7;
	   hdr.ids.r8 = local_metadata.r8;
	   hdr.ids.r9 = local_metadata.r9;
	   hdr.ids.r10 = local_metadata.r10;
	   
	   hdr.ids.src_address = local_metadata.src_address;
           hdr.ids.dst_address = local_metadata.dst_address;
           hdr.ids.src_port = local_metadata.src_port;
           hdr.ids.dst_port = local_metadata.dst_port;           
	}
    }
}

#endif
