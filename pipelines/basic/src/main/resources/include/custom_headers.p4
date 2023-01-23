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

#ifndef __CUSTOM_HEADERS__
#define __CUSTOM_HEADERS__

const bit<8> RESUB_FL_1  = 0;

struct headers_t {
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
    ids_t ids;
}

struct local_metadata_t {
    bit<16>       l4_src_port;
    bit<16>       l4_dst_port;
    next_hop_id_t next_hop_id;
    bit<16>       tcp_length;
    
    @field_list(RESUB_FL_1) bit<32> reg_index;
    @field_list(RESUB_FL_1) _BOOL  report;
    @field_list(RESUB_FL_1) _BOOL  hash_collusion;
    //r fields are defined for debugging purposes
    @field_list(RESUB_FL_1) bit<32> r1;
    @field_list(RESUB_FL_1) bit<64> r2;
    @field_list(RESUB_FL_1) bit<32> r3;
    @field_list(RESUB_FL_1) bit<64> r4;
    @field_list(RESUB_FL_1) bit<64> r5;
    @field_list(RESUB_FL_1) bit<32> r6;
    @field_list(RESUB_FL_1) bit<64> r7;
    @field_list(RESUB_FL_1) bit<32> r8;
    @field_list(RESUB_FL_1) bit<64> r9;
    @field_list(RESUB_FL_1) bit<64> r10;
    @field_list(RESUB_FL_1) bit<32> src_address;
    @field_list(RESUB_FL_1) bit<32> dst_address;
    @field_list(RESUB_FL_1) bit<16> src_port;
    @field_list(RESUB_FL_1) bit<16> dst_port;

    bit<32> flow_hash_1;
    bit<32> flow_hash_2;
    bit<32> r_pointer;

    //for similarity calc.
    bit<32> c_packets;
    bit<32> c_bytes;
    bit<32> centroid_n_bytes; //centroid normal for bits
    bit<32> centroid_n_packets; //centroid normal for packets
    bit<32> centroid_abn_bytes; //centroid abnormal for bits
    bit<32> centroid_abn_packets; //centroid abnormal for packets
}

#endif
