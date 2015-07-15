# -*- coding: utf-8 -*-

import argparse
import datetime

from zsflow.db import DB
from zsflow.main import DB_NAME


monitor_type = None


def init_args():
    parser = argparse.ArgumentParser(description="Zabbix sFlow Script")

    parser.add_argument("--type", action="store",
                        dest="type", help="monitor type",
                        default="UDP")
    args = parser.parse_args()

    global monitor_type

    monitor_type = args.type

    return args


def run():
    status = DB(DB_NAME).query_status()
    for s in status:
        state = s[0]
        src_ip = s[1]
        src_port = s[2]
        dest_ip = s[3]
        dest_port = s[4]
        dt = s[5]
        type_ = s[6]

        def dt_ok(dt):
            now = datetime.datetime.now()
            dt = datetime.datetime.strptime(dt, '%y-%m-%d %H:%M:%S')
            return now - datetime.timedelta(seconds=300) < dt

        if (type_.upper() == monitor_type.upper() and
            state == "BAD" and
            dt_ok(dt)):
            print("{s}-{si}-{sp}-{di}-{dp}".format(
                s=monitor_type.upper(),
                si=src_ip, sp=src_port,
                di=dest_ip, dp=dest_port
            ))
            break
        else:
            pass
    else:
        print("UDP-GOOD")


run_cnt = 0
def main():
    init_args()
    global run_cnt
    run_cnt += 1
    try:
        run()
    except Exception as e:
        if run_cnt <= 5:
            main()
        else:
            print("UDP-UNKNOWN")

