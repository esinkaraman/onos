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

control registers_ingress(inout headers_t hdr,
                              inout standard_metadata_t standard_metadata) {

    //cluster centroid registers
    register<bit<32>>(2) c;

    register<bit<32>>(128) pc;
    register<bit<32>>(128) bc;

    bit<32> flow_hash_1;
    bit<32> flow_hash_2;

    apply {
       //if IDS Init
       if (hdr.ids.isValid() && hdr.ids.type == 0x1) {
            c.write(0, (bit<32>)hdr.ids.cnt_n);
            c.write(1, (bit<32>)hdr.ids.cnt_abn);
       }

        // if TCP
        if (hdr.ipv4.isValid() && hdr.ipv4.protocol == 0x6) {
            //calculate flow hash 1
            hash(flow_hash_1, HashAlgorithm.crc32,
                10w0,
                { hdr.ipv4.src_addr, hdr.ipv4.dst_addr,
                hdr.ipv4.protocol, hdr.tcp.src_port, hdr.tcp.dst_port },
                10w1023);
            //calculate flow hash 2
            hash(flow_hash_2, HashAlgorithm.crc32,
                10w0,
                { hdr.ipv4.dst_addr, hdr.ipv4.src_addr,
                hdr.ipv4.protocol, hdr.tcp.dst_port, hdr.tcp.src_port },
                10w1023);
             //calculate register index
             bit<32> reg_index_common;

             reg_index_common = (flow_hash_1 ^ flow_hash_2) % 128;

             if (hdr.tcp.ctrl == 0x002) {
                //TCP SYN, reset the register
                pc.write(reg_index_common, (bit<32>)0x1);
                bc.write(reg_index_common, standard_metadata.packet_length);

              } else {
                //read the registers first
                bit<32> p_count;
                bit<32> p_bytes;
                //read from oppsite direction and write to the own register
                pc.read(p_count, reg_index_common);
                pc.write(reg_index_common, p_count + 1);
                //read paket bytes from the oppsite direction and update the value
                bc.read(p_bytes, reg_index_common);
                bc.write(reg_index_common, p_bytes + standard_metadata.packet_length);

              }
        }
    }
}

