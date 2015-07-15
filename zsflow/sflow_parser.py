# -*- coding: utf-8 -*-

# sFlow version 5 document: http://www.sflow.org/sflow_version_5.txt

import logging
import struct
from socket import ntohl
from xdrlib import Unpacker


FORMAT_FLOW_SAMPLE = 1
FORMAT_COUNTER_SAMPLE = 2
FORMAT_EXPANDED_FLOW_SAMPLE = 3
FORMAT_EXPANDED_COUNTER_SAMPLE = 4

FORMAT_COUNTER_RECORD_GENERIC = 1
FORMAT_COUNTER_RECORD_ETHERNET = 2
FORMAT_COUNTER_RECORD_TOKENRING = 3
FORMAT_COUNTER_RECORD_100BASEVG = 4
FORMAT_COUNTER_RECORD_VLAN = 5
FORMAT_COUNTER_RECORD_PROCESS = 1001

FORMAT_FLOW_RECORD_RAW_PACKET = 1
FORMAT_FLOW_RECORD_ETHERNET_FRAME = 2
FORMAT_FLOW_RECORD_IPv4 = 3
FORMAT_FLOW_RECORD_IPv6 = 4
FORMAT_FLOW_RECORD_EXTENDED_SWITCH = 1001
FORMAT_FLOW_RECORD_EXTENDED_ROUTER = 1002
FORMAT_FLOW_RECORD_EXTENDED_GATEWAY = 1003
FORMAT_FLOW_RECORD_USER = 1004
FORMAT_FLOW_RECORD_EXTENDED_URL = 1005
FORMAT_FLOW_RECORD_EXTENDED_MPLS = 1006
FORMAT_FLOW_RECORD_EXTENDED_NAT = 1007
FORMAT_FLOW_RECORD_EXTENDED_MPLS_TUNNEL = 1008
FORMAT_FLOW_RECORD_EXTENDED_MPLS_VC = 1009
FORMAT_FLOW_RECORD_EXTENDED_MPLS_FEC = 1010
FORMAT_FLOW_RECORD_EXTENDED_MPLS_LVP = 1011
FORMAT_FLOW_RECORD_EXTENDED_VLAN_TUNNEL = 1012

HEADER_PROTO_ETHERNET_ISO88023 = 1

ETHER_TYPE_IEEE8021Q = 0x8100
ETHER_TYPE_IPv4 = 0x0800
ETHER_TYPE_ARP = 0x0806


def get_uint(data, offset):
    d = struct.unpack("!B", data[offset])
    return d[0]

def get_mac_str(binary_mac):
    offset_0 = get_uint(binary_mac, 0)
    offset_1 = get_uint(binary_mac, 1)
    offset_2 = get_uint(binary_mac, 2)
    offset_3 = get_uint(binary_mac, 3)
    offset_4 = get_uint(binary_mac, 4)
    offset_5 = get_uint(binary_mac, 5)
    return "%02X:%02X:%02X:%02X:%02X:%02X" % (
        offset_0,
        offset_1,
        offset_2,
        offset_3,
        offset_4,
        offset_5
    )

def get_ip_str(binary_ip):
    return "%d.%d.%d.%d" % (
        get_uint(binary_ip, 0),
        get_uint(binary_ip, 1),
        get_uint(binary_ip, 2),
        get_uint(binary_ip, 3)
    )


class SFlowPacket(object):

    def __init__(self):
        self.version = None
        self.agent_ip_version = None
        self.agent_ip_address = None
        self.sub_agent_id = None
        self.datagram_sequence_num = None
        self.switch_uptime = None # unit in ms
        self.sample_amount = None

        self.flow_samples = []
        self.counter_samples = []


class EthernetHeader(object):

    def __init__(self, header):
        self.dest_mac = get_mac_str(header[0:6])
        self.src_mac = get_mac_str(header[6:12])
        self.ether_type = get_uint(header, 12)*256 + get_uint(header, 13)


class IEEE8021QHeader(object):

    def __init__(self, header):
        self.dest_mac = get_mac_str(header[0:6])
        self.src_mac = get_mac_str(header[6:12])
        self.vlan_id = get_uint(header, 14)* 56 + get_uint(header, 15)
        self.ether_type = get_uint(header, 16)*256 + get_uint(header, 17)


class TCPHeader(object):

    def __init__(self, header):
        self.src_port = get_uint(header, 0)*256 + get_uint(header, 1)
        self.dest_port = get_uint(header, 2)*256 + get_uint(header, 3)


class UDPHeader(object):

    def __init__(self, header):
        self.src_port = get_uint(header, 0)*256 + get_uint(header, 1)
        self.dest_port = get_uint(header, 2)*256 + get_uint(header, 3)


class ARPHeader(object):

    def __init__(self, header):
        self.arp_op = get_uint(header, 6)*256 + get_uint(header, 7)
        self.arp_sha = get_mac_str(header[8:14])
        self.arp_spa = get_ip_str(header[14:18])
        self.arp_tha = get_mac_str(header[18:24])
        self.arp_tpa = get_ip_str(header[24:28])


class IPv4Header(object):

    def __init__(self, header):
        self.version = (get_uint(header, 0) & 0xf0) >> 4
        self.ihl = get_uint(header, 0) & 0x0f
        self.tos = get_uint(header, 1)
        self.length = get_uint(header, 2)*256 + get_uint(header, 2)
        self.ident = get_uint(header, 4)*256 + get_uint(header, 5)
        self.flags = get_uint(header, 6) & 0x07
        self.fragment_offset = (((get_uint(header, 6) & 0xf8) >> 3)*256 +
                                get_uint(header, 7))
        self.ttl = get_uint(header, 8)
        self.protocol = get_uint(header, 9)
        self.chksum = get_uint(header, 10)*256 + get_uint(header, 11)
        self.src_ip = get_ip_str(header[12:16])
        self.dest_ip = get_ip_str(header[16:20])

        if len(header) > 20:
            self.transport_layer_header_parsed = True
            if self.protocol == 6:
                self.tcp_header = TCPHeader(header[20:])
            elif self.protocol == 17:
                self.udp_header = UDPHeader(header[20:])
        else:
            self.transport_layer_header_parsed = False

class Record(object):

    def __init__(self, sample_data):
        self.format = None


class FlowRecord(Record):

    def __init__(self, sample_data):
        super(FlowRecord, self).__init__(sample_data)
        self.parsed = True
        self.format = sample_data.unpack_uint()
        record_data = Unpacker(sample_data.unpack_opaque())

        if self.format == FORMAT_FLOW_RECORD_RAW_PACKET:
            self._parse_raw_packet(record_data)
        elif self.format == FORMAT_FLOW_RECORD_ETHERNET_FRAME:
            self._parse_ethernet_frame(record_data)
        elif self.format == FORMAT_FLOW_RECORD_IPv4:
            self._parse_ipv4(record_data)
        elif self.format == FORMAT_FLOW_RECORD_EXTENDED_SWITCH:
            self._parse_extended_switch(record_data)
        else:
            logging.warn("Format {0} is not supported now.".format(
                self.format
            ))
            self.parsed = False

    def _parse_extended_switch(self, record_data):
        self.src_vlan = record_data.unpack_uint()
        self.src_priority = record_data.unpack_uint()
        self.dest_vlan = record_data.unpack_uint()
        self.dest_priority = record_data.unpack_uint()

    def _parse_raw_packet_header(self, header):
        if len(header) < 14:
            logging.warn("RAW Packet Header too short, ignore this record.")
            self.parsed = False

        self.ether_type = get_uint(header, 12)*256 + get_uint(header, 13)
        if self.ether_type == ETHER_TYPE_IEEE8021Q:
            self._parse_ether_type_8021q(header)
        elif self.ether_type == ETHER_TYPE_ARP:
            self._parse_ether_type_arp(header)
        elif self.ether_type == ETHER_TYPE_IPv4:
            self._parse_ether_type_ipv4(header)
        else:
            logging.warn("Ether Type {0} is not supported now.".format(
                self.ether_type
            ))
            self.parsed = False

    def _parse_ether_type_arp(self, header):
        self.ether_header = EthernetHeader(header)

        if len(header) >= 14 + 28:
            self.arp_header_parsed = True
            self._parse_arp_header(header[14:])
        else:
            self.arp_header_parsed = False

    def _parse_arp_header(self, header):
        self.arp_header = ARPHeader(header)

    def _parse_ether_type_8021q(self, header):
        self.ieee8021q_header = IEEE8021QHeader(header)

        if self.ieee8021q_header.ether_type == ETHER_TYPE_ARP:
            self._parse_ether_type_arp(header)
        elif self.ieee8021q_header.ether_type == ETHER_TYPE_IPv4:
            self._parse_ether_type_ipv4(header)

    def _parse_ether_type_ipv4(self, header):
        self.ether_header = EthernetHeader(header)

        if len(header) >= 14 + 20:
            self.ipv4_header_parsed = True
            self._parse_ipv4_header(header[14:])
        else:
            self.ipv4_header_parsed = False

    def _parse_ipv4_header(self, header):
        self.ipv4_header = IPv4Header(header)

    def _parse_raw_packet(self, record_data):
        # header protocol (1=ethernet, .... 11=IPv4, 12=IPv6)
        self.header_protocol = record_data.unpack_int()
        # frame length (length before sampling)
        self.frame_length = record_data.unpack_uint()
        # stripped (number of bytes removed from the packet)
        self.stripped = record_data.unpack_uint()
        self.header = record_data.unpack_opaque()
        if self.header_protocol == HEADER_PROTO_ETHERNET_ISO88023:
            self._parse_raw_packet_header(self.header)
        else:
            logging.warn("Header Protocol {0} is not supported now.".format(
                self.header_protocol
            ))
            self.parsed = False

    def _parse_ethernet_frame(self, record_data):
        self.length = record_data.unpack_uint()
        self.src_mac = get_mac_str(record_data.unpack_fopaque(8)[0:6])
        self.dest_mac = get_mac_str(record_data.unpack_fopaque(8)[0:6])
        self.type = record_data.unpack_uint()

    def _parse_ipv4(self, record_data):
        self.length = record_data.unpack_uint()
        self.protocol = record_data.unpack_uint()
        self.src_ip = get_ip_str(record_data.unpack_fopaque(4))
        self.dst_ip = get_ip_str(record_data.unpack_fopaque(4))
        self.src_port = record_data.unpack_uint()
        self.dst_port = record_data.unpack_uint()
        self.tcp_flags = record_data.unpack_uint()
        self.tos = record_data.unpack_uint()


class CounterRecord(Record):

    def __init__(self, sample_data):
        super(CounterRecord, self).__init__(sample_data)
        self.format = sample_data.unpack_uint()
        record_data = Unpacker(sample_data.unpack_opaque())

        if self.format == FORMAT_COUNTER_RECORD_GENERIC:
            self._parse_generic(record_data)
        elif self.format == FORMAT_COUNTER_RECORD_ETHERNET:
            self._parse_ethernet(record_data)
        elif self.format == FORMAT_COUNTER_RECORD_TOKENRING:
            self._parse_tokenring(record_data)
        elif self.format == FORMAT_COUNTER_RECORD_100BASEVG:
            self._parse_100basevg(record_data)
        elif self.format == FORMAT_COUNTER_RECORD_VLAN:
            self._parse_vlan(record_data)
        elif self.format == FORMAT_COUNTER_RECORD_PROCESS:
            self._parse_process(record_data)

    def _parse_generic(self, record_data):
        self.index = record_data.unpack_uint()
        self.if_type = record_data.unpack_uint()
        self.speed = record_data.unpack_uhyper()
        self.direction = record_data.unpack_uint()
        self.status = record_data.unpack_uint()
        self.in_octets = record_data.unpack_uhyper()
        self.in_ucasts = record_data.unpack_uint()
        self.in_mcasts = record_data.unpack_uint()
        self.in_bcasts = record_data.unpack_uint()
        self.in_discards = record_data.unpack_uint()
        self.in_errors = record_data.unpack_uint()
        self.in_unknown_protos = record_data.unpack_uint()
        self.out_octets = record_data.unpack_uhyper()
        self.out_ucasts = record_data.unpack_uint()
        self.out_mcasts = record_data.unpack_uint()
        self.out_bcasts = record_data.unpack_uint()
        self.out_discards = record_data.unpack_uint()
        self.out_errors = record_data.unpack_uint()
        self.promiscuous_mode = record_data.unpack_uint()

    def _parse_ethernet(self, record_data):
        self.dot3StatsAlignmentErrors = record_data.unpack_uint()
        self.dot3StatsFCSErrors = record_data.unpack_uint()
        self.dot3StatsSingleCollisionFrames = record_data.unpack_uint()
        self.dot3StatsMultipleCollisionFrames = record_data.unpack_uint()
        self.dot3StatsSQETestErrors = record_data.unpack_uint()
        self.dot3StatsDeferredTransmissions = record_data.unpack_uint()
        self.dot3StatsLateCollisions = record_data.unpack_uint()
        self.dot3StatsExcessiveCollisions = record_data.unpack_uint()
        self.dot3StatsInternalMacTransmitErrors = record_data.unpack_uint()
        self.dot3StatsCarrierSenseErrors = record_data.unpack_uint()
        self.dot3StatsFrameTooLongs = record_data.unpack_uint()
        self.dot3StatsInternalMacReceiveErrors = record_data.unpack_uint()
        self.dot3StatsSymbolErrors = record_data.unpack_uint()

    def _parse_tokenring(self, record_data):
        self.dot5StatsLineErrors = record_data.unpack_uint()
        self.dot5StatsBurstErrors = record_data.unpack_uint()
        self.dot5StatsACErrors = record_data.unpack_uint()
        self.dot5StatsAbortTransErrors = record_data.unpack_uint()
        self.dot5StatsInternalErrors = record_data.unpack_uint()
        self.dot5StatsLostFrameErrors = record_data.unpack_uint()
        self.dot5StatsReceiveCongestions = record_data.unpack_uint()
        self.dot5StatsFrameCopiedErrors = record_data.unpack_uint()
        self.dot5StatsTokenErrors = record_data.unpack_uint()
        self.dot5StatsSoftErrors = record_data.unpack_uint()
        self.dot5StatsHardErrors = record_data.unpack_uint()
        self.dot5StatsSignalLoss = record_data.unpack_uint()
        self.dot5StatsTransmitBeacons = record_data.unpack_uint()
        self.dot5StatsRecoverys = record_data.unpack_uint()
        self.dot5StatsLobeWires = record_data.unpack_uint()
        self.dot5StatsRemoves = record_data.unpack_uint()
        self.dot5StatsSingles = record_data.unpack_uint()
        self.dot5StatsFreqErrors = record_data.unpack_uint()

    def _parse_100basevg(self, record_data):
        self.dot12InHighPriorityFrames = record_data.unpack_uint()
        self.dot12InHighPriorityOctets = record_data.unpack_uhyper()
        self.dot12InNormPriorityFrames = record_data.unpack_uint()
        self.dot12InNormPriorityOctets = record_data.unpack_uhyper()
        self.dot12InIPMErrors = record_data.unpack_uint()
        self.dot12InOversizeFrameErrors = record_data.unpack_uint()
        self.dot12InDataErrors = record_data.unpack_uint()
        self.dot12InNullAddressedFrames = record_data.unpack_uint()
        self.dot12OutHighPriorityFrames = record_data.unpack_uint()
        self.dot12OutHighPriorityOctets = record_data.unpack_uhyper()
        self.dot12TransitionIntoTrainings = record_data.unpack_uint()
        self.dot12HCInHighPriorityOctets = record_data.unpack_uhyper()
        self.dot12HCInNormPriorityOctets = record_data.unpack_uhyper()
        self.dot12HCOutHighPriorityOctets = record_data.unpack_uhyper()

    def _parse_vlan(self, record_data):
        self.vlan_id = record_data.unpack_uint()
        self.octets = record_data.unpack_uhyper()
        self.ucastPkts = record_data.unpack_uint()
        self.multicastPkts = record_data.unpack_uint()
        self.broadcastPkts = record_data.unpack_uint()
        self.discards = record_data.unpack_uint()

    def _parse_process(self, record_data):
        self.cpu_percentage_in_5s = record_data.unpack_uint()
        self.cpu_percentage_in_1m = record_data.unpack_uint()
        self.cpu_percentage_in_5m = record_data.unpack_uint()
        self.total_memory = record_data.unpack_hyper()
        self.free_memory = record_data.unpack_hyper()


class Sample(object):

    def __init__(self, packet, data):
        self.enterprise = 0
        self.format = None


class FlowSample(Sample):

    def __init__(self, packet, data):
        super(FlowSample, self).__init__(packet, data)
        self.format = FORMAT_FLOW_SAMPLE

        self.sequence_number = None
        self.source_id = None
        self.sampling_rate = None
        self.sample_pool = None
        self.drops = None
        self.input_if = None
        self.output_if = None
        self.record_amount = None
        self.records = []

        sample_data = Unpacker(data.unpack_opaque())
        self._parse(packet, sample_data)

    def _parse(self, packet, sample_data):
        # sample sequence number
        self.sequence_number = sample_data.unpack_uint()
        # source id
        self.source_id = sample_data.unpack_uint()
        # sampling rate
        self.sampling_rate = sample_data.unpack_uint()
        # sample pool (total number of packets that could have been sampled)
        self.sample_pool = sample_data.unpack_uint()
        # drops (packets dropped due to a lack of resources)
        self.drops = sample_data.unpack_uint()
        # input (SNMP ifIndex of input interface, 0 if not known)
        self.input_if = sample_data.unpack_uint()
        # output (SNMP ifIndex of output interface, 0 if not known)
        # broadcast or multicast are handled as follows: the
        # first bit indicates multiple destinations, the
        # lower order bits number of interfaces
        self.output_if = sample_data.unpack_uint()

        self.record_amount = sample_data.unpack_uint()
        for _ in range(0, self.record_amount):
            fr = FlowRecord(sample_data)
            if fr.parsed:
                self.records.append(fr)


class CounterSample(Sample):

    def __init__(self, packet, data):
        super(CounterSample, self).__init__(packet, data)
        self.format = FORMAT_COUNTER_SAMPLE

        self.sequence_num = None
        self.source_id = None
        self.record_amount = None
        self.records = []

        sample_data = Unpacker(data.unpack_opaque())
        self._parse(packet, sample_data)

    def _parse(self, packet, sample_data):
        # sample sequence number
        self.sequence_num = sample_data.unpack_uint()
        # source id
        self.source_id = sample_data.unpack_uint()

        self.record_amount = sample_data.unpack_uint()
        for _ in range(0, self.record_amount):
            self.records.append(CounterRecord(sample_data))


class SPManager(object):

    def __init__(self):
        pass

    def parse(self, raw_data):
        packet = SFlowPacket()
        data = Unpacker(raw_data)

        # sFlow version (2|4|5)
        packet.version = data.unpack_uint()
        if packet.version != 5:
            logging.error("Only support version 5.")
            raise RuntimeError("Only support version 5.")
        logging.debug("Get version {0}".format(packet.version))

        # IP version of the Agent/Switch (1=v4|2=v6)
        packet.agent_ip_version = data.unpack_uint()
        if packet.agent_ip_version != 1:
            logging.error("Only support IPv4.")
            raise RuntimeError("Only support IPv4.")

        # Agent IP address (v4=4byte|v6=16byte)
        packet.agent_ip_address = ntohl(data.unpack_uint())

        # sub agent id
        packet.sub_agent_id = data.unpack_uint()

        # datagram sequence number
        packet.datagram_sequence_num = data.unpack_uint()

        # switch uptime in ms
        packet.switch_uptime = data.unpack_uint()

        # how many samples in datagram
        packet.sample_amount = data.unpack_uint()

        self._parse_samples(packet, data)

        return packet

    def _parse_samples(self, packet, data):
        for _ in range(0, packet.sample_amount):
            # data format sample data (20 bit enterprise & 12 bit format)
            # (standard enterprise 0, formats 1,2,3,4)
            format_ = data.unpack_uint()
            if format_ == FORMAT_FLOW_SAMPLE:
                packet.flow_samples.append(FlowSample(packet, data))
            elif format_ == FORMAT_COUNTER_SAMPLE:
                packet.counter_samples.append(CounterSample(packet, data))
            else:
                logging.error("Sample format {0} is not supported now.".format(
                    format_
                ))
                raise RuntimeError("Sample format {0} is not "
                                   "supported now.".format(format_))

