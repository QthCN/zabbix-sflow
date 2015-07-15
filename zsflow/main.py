# -*- coding: utf-8 -*-

import argparse
import datetime
import os
import time
import Queue
from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR

from db import DB
from zsflow import sflow_parser

header = None
sampling = None
polling = None
port = None
udp_threshold = None

DB_NAME = "zsflow.db"
INTERVAL = 15

PACKET_QUEUE = Queue.Queue()


def init_args():
    parser = argparse.ArgumentParser(description="Zabbix sFlow Collector")

    parser.add_argument("--header", action="store",
                        dest="header", help="sFlow sampling header length",
                        default=64)
    parser.add_argument("--sampling", action="store",
                        dest="sampling", type=int,
                        help="sFlow sampling", default=5)
    parser.add_argument("--polling", action="store", dest="polling",
                        type=int, default=3)
    parser.add_argument("--port", action="store", dest="port",
                        help="sFlow collector listen port",
                        default=6343)
    parser.add_argument("--udp-threshold", action="store",
                        dest="udp_threshold",
                        help="UDP Threshold",
                        default=10000)
    args = parser.parse_args()

    global header
    global sampling
    global polling
    global port
    global udp_threshold

    header = args.header
    sampling = args.sampling
    polling = args.polling
    port = args.port
    udp_threshold = int(args.udp_threshold)

    return args


def start_worker(sock):
    w_cnt = 1
    for w in range(0, w_cnt):
        pid = os.fork()
        if pid < 0:
            print("Fork process failed.")
        elif pid > 0:
            print("Fork process successful, pid is %d" % pid)
            break
        else:
            if w + 1 == w_cnt:
                return
    # in new process
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            do(data)
        except Exception as e:
            print(str(e))
            pass
    # TODO(tianhuan) close sock


def sync_status():
    sync_udp_status()


def sync_udp_status():
    now = datetime.datetime.now()
    before = now - datetime.timedelta(seconds=INTERVAL)
    records = DB(DB_NAME).query_record("UDP", before, now)
    if len(records) == 0:
        return

    stat = dict()
    for record in records:
        src_ip = record[0]
        src_port = record[1]
        dest_ip = record[2]
        dest_port = record[3]
        key = "{si}-{sp}-{di}-{dp}".format(si=src_ip,
                                           sp=src_port,
                                           di=dest_ip,
                                           dp=dest_port)
        if key in stat:
            stat[key] += 1
        else:
            stat[key] = 1

    max_record_key = None
    max_record_cnt = 0
    for key in stat:
        if stat[key] > max_record_cnt:
            max_record_cnt = stat[key]
            max_record_key = key

    total_pkt_speed = len(records) * sampling / INTERVAL
    if total_pkt_speed >= udp_threshold:
        DB(DB_NAME).update_status(t="UDP",
                                  status="BAD",
                                  src_ip=max_record_key.split("-")[0],
                                  src_port=int(max_record_key.split("-")[1]),
                                  dest_ip=max_record_key.split("-")[2],
                                  dest_port=int(max_record_key.split("-")[3]),
                                  dt=datetime.datetime.now())

def run():
    listen_addr = ("0.0.0.0", port)
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    sock.bind(listen_addr)
    start_worker(sock)
    while True:
        try:
            sync_status()
        except Exception as e:
            print(str(e))
        time.sleep(INTERVAL)

    # TODO(tianhuan) no clean codes here


def do(data):
    sp_mgr = sflow_parser.SPManager()
    packet = sp_mgr.parse(data)

    for sample in packet.flow_samples:
        for record in sample.records:
            if record.format == sflow_parser.FORMAT_FLOW_RECORD_RAW_PACKET:
                analyze_raw_record(record)


def analyze_raw_record(record):
    if record.ether_type == sflow_parser.ETHER_TYPE_IPv4:
        analyze_ipv4_record(record)
    elif record.ether_type == sflow_parser.ETHER_TYPE_ARP:
        analyze_arp_record(record)
    elif record.ether_type == sflow_parser.ETHER_TYPE_IEEE8021Q:
        if record.ieee8021q_header.ether_type == sflow_parser.ETHER_TYPE_IPv4:
            analyze_ipv4_record(record)
        elif record.ieee8021q_header.ether_type == sflow_parser.ETHER_TYPE_ARP:
            analyze_arp_record(record)
    else:
        print("Ether type {0} is not supported.".format(
            record.ether_type
        ))


def analyze_tcp_record(record):
    pass


def analyze_udp_record(record):
    src_ip = record.ipv4_header.src_ip
    dest_ip = record.ipv4_header.dest_ip
    src_port = record.ipv4_header.udp_header.src_port
    dest_port = record.ipv4_header.udp_header.dest_port
    DB(DB_NAME).record("UDP", src_ip, src_port, dest_ip, dest_port)


def analyze_ipv4_record(record):
    if (record.ipv4_header_parsed and
            record.ipv4_header.transport_layer_header_parsed):
        if record.ipv4_header.protocol == 6:
            analyze_tcp_record(record)
        elif record.ipv4_header.protocol == 17:
            analyze_udp_record(record)


def analyze_arp_record(record):
    if record.arp_header_parsed:
        pass


def init_db():
    db = DB(DB_NAME)
    db.init()


if __name__ == "__main__":
    args = init_args()
    init_db()
    run()

