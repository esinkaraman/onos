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



#include "headers.p4"
#include "defines.p4"

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

#define FLOW_TIMEOUT 2000000 //2 seconds

const bit<32> REG_SIZE = 32768;

control registers_ingress(inout headers_t hdr,
			      inout local_metadata_t local_metadata,
                              inout standard_metadata_t standard_metadata) {



    //cluster centroid register
    register<bit<32>>(4) c;

    register<bit<32>>(REG_SIZE) pc; //packet counter
    register<bit<32>>(REG_SIZE) bc; //byte counter
    register<bit<32>>(1) p; //register pointer

    register<bit<32>>(REG_SIZE) src_addr_reg; //src ip
    register<bit<32>>(REG_SIZE) dst_addr_reg; //dst ip
    register<bit<16>>(REG_SIZE) src_port_reg; //src port
    register<bit<16>>(REG_SIZE) dst_port_reg; //dst port

    register<bit<48>>(REG_SIZE) lpt; //last packet timestamp

    register<bit<64>>(REG_SIZE) tmp; //tmp register
    register<bit<64>>(REG_SIZE) tmp2; //tmp register

    counter(1, CounterType.packets) chc; //counter for hash collusion
    counter(1, CounterType.packets) cp; //counter for all packets

    //register read(out T result, in I index);
    //register write(in I index, in T value);

    action clean_register_and_start_flow(bit<32> reg_index_common) {
           lpt.write(reg_index_common, standard_metadata.ingress_global_timestamp);

           pc.write(reg_index_common, (bit<32>)0x1);
           bc.write(reg_index_common, standard_metadata.packet_length);
	
	   src_addr_reg.write(reg_index_common, hdr.ipv4.src_addr);
	   dst_addr_reg.write(reg_index_common, hdr.ipv4.dst_addr);
	   src_port_reg.write(reg_index_common, hdr.tcp.src_port);
	   dst_port_reg.write(reg_index_common, hdr.tcp.dst_port);
    }

    action update_flow_counters(bit<32> reg_index_common) {
        //read and update packet count
        pc.read(local_metadata.c_packets, reg_index_common);
        pc.write(reg_index_common, local_metadata.c_packets + 1);
        //read and update packet bytes
        bc.read(local_metadata.c_bytes, reg_index_common);
        bc.write(reg_index_common, local_metadata.c_bytes + standard_metadata.packet_length);	
	//update last packet timestamp register
	lpt.write(reg_index_common, standard_metadata.ingress_global_timestamp);
    }
    
    apply {
       //if IDS Init
       if (hdr.ids.isValid() && hdr.ids.type == 0x1) {
            c.write(0, (bit<32>)hdr.ids.cnt_n_bytes);
	    c.write(1, (bit<32>)hdr.ids.cnt_n_packets);
            c.write(2, (bit<32>)hdr.ids.cnt_abn_bytes);
	    c.write(3, (bit<32>)hdr.ids.cnt_abn_packets);
       }
	
	if (!hdr.ids.isValid()) {
		//count all packets
		cp.count(0);
	}
	//if IDS Resubmit
	if (hdr.ids.isValid() && hdr.ids.type == 0x2) {
		if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_NORMAL) {
			//reset the pointer at the beginning of the resubmit loop
	     		p.write(0, 0);
		}
                local_metadata.report = false;
		p.read(local_metadata.r_pointer, 0);
		if (local_metadata.r_pointer < REG_SIZE) {
		     //increase r_pointer right after reading it, if icinde problem olursa takilmadan diger index ile devam etsin
		     p.write(0, local_metadata.r_pointer + 1);
		     //instance type can be normal or resubmit
		     //DO SIMILARITY CALCULATION
		     //read counters
		     pc.read(local_metadata.c_packets, local_metadata.r_pointer);
		     //do not consider empty flow data
		     if (local_metadata.c_packets != 0) {
		     	     bc.read(local_metadata.c_bytes, local_metadata.r_pointer);
		     	     //read cenroid values
			     c.read(local_metadata.centroid_n_bytes, 0);
			     c.read(local_metadata.centroid_n_packets, 1);
			     c.read(local_metadata.centroid_abn_bytes, 2);
			     c.read(local_metadata.centroid_abn_packets, 3);
			     //calc similarity to normal cluster
			     int<32> subt;
			     int<64> multp;
			     int<64> s1;
			     int<64> s2;

			     subt = ((int<32>)local_metadata.c_bytes) - ((int<32>)local_metadata.centroid_n_bytes);
			     local_metadata.r1 = (bit<32>)subt;//
			     multp = ((int<64>)subt) * ((int<64>)subt);
			     local_metadata.r2 = (bit<64>)multp;
			     s1 = multp;
		
			     subt = ((int<32>)local_metadata.c_packets) - ((int<32>)local_metadata.centroid_n_packets);
			     local_metadata.r3 = (bit<32>)subt;//	
			     multp = ((int<64>)subt) * ((int<64>)subt);
			     local_metadata.r4 = (bit<64>)multp;//
			     s1 = s1 + multp;
			     local_metadata.r5 = (bit<64>)s1;//
			     
			     //calc similarit to abnormal cluster
			     subt = ((int<32>)local_metadata.c_bytes) - ((int<32>)local_metadata.centroid_abn_bytes);
			     local_metadata.r6 = (bit<32>)subt;//
			     multp = ((int<64>)subt) * ((int<64>)subt);
			     local_metadata.r7 = (bit<64>)multp;//
			     s2 = multp;
		
			     subt = ((int<32>)local_metadata.c_packets) - ((int<32>)local_metadata.centroid_abn_packets);
			     local_metadata.r8 = (bit<32>)subt;//
			     multp = ((int<64>)subt) * ((int<64>)subt);
			     local_metadata.r9 = (bit<64>)multp;//
			     s2 = s2 + multp;
			     local_metadata.r10 = (bit<64>)s2;//
			     tmp.write(local_metadata.r_pointer, (bit<64>)s1);
                             tmp2.write(local_metadata.r_pointer, (bit<64>)s2);

			     //compare s1 and s1 and to which cluster the current session is closer
			     if (s2 < s1) {
			     	//closer to the abnormal cluster, report it
				
		                local_metadata.report = true;
				local_metadata.reg_index = local_metadata.r_pointer;
			     	//reset session data in the register after detecting anomaly
			     	/* do not register for now, can detect it more than once nop, only new tcp session will reset the register
				pc.write(local_metadata.r_pointer, 0);
			     	bc.write(local_metadata.r_pointer, 0);
			
				src_addr_reg.read(local_metadata.src_address, local_metadata.r_pointer);
				dst_addr_reg.read(local_metadata.dst_address, local_metadata.r_pointer);
				src_port_reg.read(local_metadata.src_port, local_metadata.r_pointer);
				dst_port_reg.read(local_metadata.dst_port, local_metadata.r_pointer);	
				//also reset registers containing header info
	        		src_addr_reg.write(reg_index_common, 0);
			        dst_addr_reg.write(reg_index_common, 0);
	        		src_port_reg.write(reg_index_common, 0);
	        		dst_port_reg.write(reg_index_common, 0);*/		
			     }
		     }
		     resubmit_preserving_field_list(RESUB_FL_1);
		} else {
		     mark_to_drop(standard_metadata);
		}
        }

        // if TCP
        if (hdr.ipv4.isValid() && hdr.ipv4.protocol == 0x6) {
            //calculate flow hash 1
            hash(local_metadata.flow_hash_1, HashAlgorithm.crc32,
                10w0,
                { hdr.ipv4.src_addr, hdr.ipv4.dst_addr,
                hdr.ipv4.protocol, hdr.tcp.src_port, hdr.tcp.dst_port },
                (bit<32>)REG_SIZE);
            //calculate flow hash 2
            hash(local_metadata.flow_hash_2, HashAlgorithm.crc32,
                10w0,
                { hdr.ipv4.dst_addr, hdr.ipv4.src_addr,
                hdr.ipv4.protocol, hdr.tcp.dst_port, hdr.tcp.src_port },
                (bit<32>)REG_SIZE);

             //calculate register index
             bit<32> reg_index_common;
             reg_index_common = (local_metadata.flow_hash_1 ^ local_metadata.flow_hash_2) % REG_SIZE;
	     
             if (hdr.tcp.ctrl == 0x002) {
		//TCP SYN
		bit<48> last_packet_time;
		lpt.read(last_packet_time,reg_index_common);
		if (last_packet_time == 0 || (standard_metadata.ingress_global_timestamp - last_packet_time) > FLOW_TIMEOUT) {
			//flow timeout occured, reset the register and start a new flow
			clean_register_and_start_flow(reg_index_common);
		} else {
			bit<32> srca;
			bit<32> dsta;
			bit<16> srcp;
			bit<16> dstp;
		        src_addr_reg.read(srca, reg_index_common);
		        dst_addr_reg.read(dsta, reg_index_common);
		        src_port_reg.read(srcp, reg_index_common);
		        dst_port_reg.read(dstp, reg_index_common);
			//check header info
			if (srca == hdr.ipv4.src_addr && dsta == hdr.ipv4.dst_addr && 
				srcp == hdr.tcp.src_port && dstp == hdr.tcp.dst_port) {
				//no flow timeout occurred, starting a new flow with the same header
				update_flow_counters(reg_index_common);
			} else {
				//hash collusion occurred
				local_metadata.hash_collusion = true;
				chc.count(0);
			}
		}
              } else {
		bit<32> srca;
		bit<32> dsta;
		bit<16> srcp;
		bit<16> dstp;
		src_addr_reg.read(srca, reg_index_common);
		dst_addr_reg.read(dsta, reg_index_common);
		src_port_reg.read(srcp, reg_index_common);
		dst_port_reg.read(dstp, reg_index_common);
		
		//be sure updating a valid flow, colliding flows has already been reported
		if ((srca == hdr.ipv4.src_addr && dsta == hdr.ipv4.dst_addr && 
				srcp == hdr.tcp.src_port && dstp == hdr.tcp.dst_port) || 
			(srca == hdr.ipv4.dst_addr && dsta == hdr.ipv4.src_addr && 	
				srcp == hdr.tcp.dst_port && dstp == hdr.tcp.src_port)) {
			update_flow_counters(reg_index_common);
		}
              }
        }
    }
}


