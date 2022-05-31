import dpkt
import sys
import socket

import datetime
from loguru import logger

def packet_parser(filepath, ip_src, save_filepath):
    packets_count = 0
    pcap_in = open(filepath, 'rb')
    writer = dpkt.pcap.Writer(open(save_filepath, "wb"))
    contents = dpkt.pcap.Reader(pcap_in)       
    for ts, buf in contents:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            dst_ip = socket.inet_ntoa(ip.dst)
            src_ip = socket.inet_ntoa(ip.src)
            if src_ip == ip_src:
                logger.debug(
                    f'Пакет с заданным ip Source: {src_ip} -> Destination: {dst_ip}'
                    )
                writer.writepkt(buf, ts)
                packets_count += 1
        except Exception as e:
            logger.error(e)
    if packets_count > 0:
        logger.success(f'{packets_count} пакетов успешно записано в {save_filepath}')
    else:
        logger.warning(f'Пакетов с заданными настройками не найдено')

if __name__ == "__main__":
    packet_parser(**{
                x.split('=')[0]: x.split('=')[1]
                for x in sys.argv if '=' in x
                })
    
