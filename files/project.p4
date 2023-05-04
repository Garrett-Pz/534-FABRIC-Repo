#GARRETT PARZYCH

#include <core.p4>
#include <v1model.p4>

#define MAX_HOP_COUNT 5
#define MAX_NODE_COUNT 10

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

const bit<16> TYPE_IPv4 = 0x0800;
const bit<16> TYPE_CONNECTION = 0x1212;
const bit<16> TYPE_EMISSION = 0x3232;
const bit<16> NO_FIRST_MATCH = 0x5050;
const bit<16> ALREADY_MATCHED = 0x5151;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header connection_t {
    bit<32> hopAddr;
    bit<16> nextHdr;
}

header emission_t {
  bit<32> srcAddr;
  bit<32> dstAddr;
  bit<16> nextHdr;
}

struct metadata {

}

struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    connection_t[MAX_HOP_COUNT]  stack;
    emission_t[MAX_NODE_COUNT] emission;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
      transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
          TYPE_IPv4: parse_ipv4;
          TYPE_CONNECTION: parse_connection_helper;

          TYPE_EMISSION: parse_emission;
          NO_FIRST_MATCH: parse_emission;
          ALREADY_MATCHED: parse_emission;

          default: accept;
        }
    }

    state parse_ipv4 {
      packet.extract(hdr.ipv4);
      transition accept;
    }

    state parse_connection_helper {
        packet.extract(hdr.ipv4);
        transition parse_connection;
    }

    state parse_connection {
        packet.extract(hdr.stack.next);
        transition select(hdr.stack.last.nextHdr) {
            TYPE_CONNECTION: parse_connection;
            0x0: accept;
            default: accept;
        }
    }

    state parse_emission {
        packet.extract(hdr.emission.next);
        transition select(hdr.emission.last.nextHdr) {
            TYPE_EMISSION: parse_emission;
            0x0: accept;
            default: accept;
        }
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control manageStack(inout headers hdr, in bit<32> switchAddr) {
    apply{
        if(hdr.stack[0].isValid()) {
            hdr.stack.push_front(1);

            hdr.stack[0].setValid();
            hdr.stack[0].hopAddr = switchAddr;
            hdr.stack[0].nextHdr = TYPE_CONNECTION;
        }
        else {  // If not valid, this is first switch in path
            hdr.stack[0].setValid();
            hdr.stack[0].hopAddr = switchAddr;
            hdr.stack[0].nextHdr = TYPE_CONNECTION;

            hdr.stack[1].setValid();
            hdr.stack[1].hopAddr = hdr.ipv4.srcAddr;
            hdr.stack[1].nextHdr = 0x0;

            hdr.ethernet.etherType = TYPE_CONNECTION;
        }
    }
}


control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    bit<32> tmp = 0x0;
    manageStack() manage_stack;

    action ipv4_forward(egressSpec_t port, bit<32> switchAddr) {
        standard_metadata.egress_spec = port;
        tmp = switchAddr;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action clone_packet() {
        const bit<32> REPORT_MIRROR_SESSION_ID = 500;
        clone(CloneType.I2E, REPORT_MIRROR_SESSION_ID);
    }

    action emission_src_match() {
        tmp = 0x1;
    }

    action emission_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table emission_src {
        key = {
            hdr.emission[0].srcAddr: exact;
        }
        actions = {
            emission_src_match;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table emission_dst {
        key = {
            hdr.emission[0].dstAddr: exact;
        }
        actions = {
            emission_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if(hdr.ipv4.isValid()) {
          ipv4_lpm.apply();
          manage_stack.apply(hdr, tmp);
        }
        else if (hdr.emission[0].isValid()) {
            emission_src.apply();
            if(tmp == 1) {
                // Match was found

                emission_dst.apply();
                tmp = 0x0;
                clone_packet();
            }
            else if(hdr.ethernet.etherType == ALREADY_MATCHED) {
                // No match found, but one was found previously

                mark_to_drop(standard_metadata);
            }
            else {
                // No match found yet

                hdr.ethernet.etherType = NO_FIRST_MATCH;
            }
        }
        else {
          mark_to_drop(standard_metadata);
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {
        if(hdr.ethernet.etherType == TYPE_EMISSION ||
        hdr.ethernet.etherType == NO_FIRST_MATCH ||
        hdr.ethernet.etherType == ALREADY_MATCHED) {

            hdr.emission.pop_front(1);
            if(hdr.ethernet.etherType == NO_FIRST_MATCH) {
                hdr.ethernet.etherType = TYPE_EMISSION;
                recirculate_preserving_field_list(0);
            }
            else if(standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE) {
                hdr.ethernet.etherType = ALREADY_MATCHED;
                recirculate_preserving_field_list(0);
            }
            else {
                hdr.ethernet.etherType = TYPE_EMISSION;
            }
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.stack);
        packet.emit(hdr.emission);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
