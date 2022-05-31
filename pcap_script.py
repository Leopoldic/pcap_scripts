import dpkt
import sys
import socket

import datetime
from loguru import logger


class PacketReader:
    
    def __init__(self):
        self.new_packets = []
        self.keys = ['filepath', 'ip_src', 'save_filepath']
        if self.packet_initialise():
            self.packet_parse()
            self.save_new_packet()


    def packet_initialise(self):
        self.reader_settings = {
                x.split('=')[0]: x.split('=')[1]
                for x in sys.argv if '=' in x
                }
        if list(self.reader_settings.keys()) != self.keys:
            logger.warning('Не все параметры указаны')
            return False
        return True

    def packet_parse(self):
        pcap_in = open(self.reader_settings['filepath'], 'rb')
        contents = dpkt.pcap.Reader(pcap_in)       
        for ts, buf in contents:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                dst_ip = socket.inet_ntoa(ip.dst)
                src_ip = socket.inet_ntoa(ip.src)
                if src_ip == self.reader_settings['ip_src']:
                    logger.debug(
                        f'Пакет с заданным ip Source: {src_ip} -> Destination: {dst_ip}'
                        )
                    self.new_packets.append({'info':buf,'property':ts})
            except Exception as e:
                logger.error(e)

    def save_new_packet(self):
        f = open(self.reader_settings['save_filepath'], "wb")
        writer = dpkt.pcap.Writer(f)
        if len(self.new_packets) > 0:
            [writer.writepkt(packet['info'], packet['property']) for packet in self.new_packets]
            logger.success(
                f"Пакеты успешно сохранены в {self.reader_settings['save_filepath']}"
                )
        else:
            logger.warning(
                'Пакетов с подобными настройками не найдено.'
            )

if __name__ == "__main__":
    PacketReader()