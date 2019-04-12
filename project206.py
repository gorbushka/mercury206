#!/usr/bin/python
# coding: utf-8
# fork https://github.com/n0l/Mercury_remote/blob/master/get_data_python3.py
# fork https://github.com/sergray/energy-meter-mercury206
# protocol https://www.incotexcom.ru/files/em/docs/mercury-protocol-obmena-1.pdf
# Semikin@powernet 2019
import re
import socket
import time
import sys
import struct
from struct import pack, unpack
import traceback
#from minimalmodbus import _calculateCrcString as modbus_crc

def upper_hex(byte):
    r"""
    >>> upper_hex('\x00')
    '00'
    >>> upper_hex(0x0)
    '00'
    >>> upper_hex(5)
    '05'
    """
    if isinstance(byte, str):
        byte = ord(byte)
    return '%02X' % byte


def pretty_hex(byte_string):
    r"""
    >>> pretty_hex('Python')
    '50 79 74 68 6F 6E'
    >>> pretty_hex('\x00\xa1\xb2')
    '00 A1 B2'
    >>> pretty_hex([1, 2, 3, 5, 8, 13])
    '01 02 03 05 08 0D'
    """
    return ' '.join(upper_hex(c) for c in byte_string)


def digitize(byte_string):
    r"""
    >>> digitize('\x00\x12\x34')
    1234
    """
    str_num = ''.join(upper_hex(b) for b in byte_string)
    return int(str_num)


def digitized_triple(data):
    r"""
    >>> digitized_triple('\x01\x23\x45\x67\x89' * 3)
    [234567.89, 12345.67, 890123.45]
    """
    return [digitize(data[i:i+4]) / 100.0 for i in range(1, 13, 4)]

def crc16(data):
    crc = 0xFFFF 
    l = len(data)
    i = 0
    while i < l:
        j = 0
        crc = crc ^ data[i]
        while j < 8:
            if (crc & 0x1):
                mask = 0xA001
            else:
                mask = 0x00
            crc = ((crc >> 1) & 0x7FFF) ^ mask
            j += 1
        i += 1
    if crc < 0:
        crc -= 256
    result = data + chr(crc % 256).encode() + chr(crc // 256).encode('latin-1')
    return result

ADDRESS_FMT = '!I'
def pack_msg(address,command):
    address=int(address)
    if isinstance(address, int):
        data = pack(ADDRESS_FMT, address)
    else:
        pad_len = len(address) % 4
        data = '\x00' * pad_len + address
    data += pack('B', command)
    msg = crc16(data)
    return msg 

def unpack_msg(message):
    r"""Unpack message string.
    Assume the first 4 bytes carry power meter address
    Return tuple with: integer power meter address and list of bytes
    >>> unpack_msg('\x00\xA6\xB7\x20\x28')
    (10925856, [40])
    >>> unpack_msg('\x00\xA6\xB7\x20\x27\x00\x26\x56\x16\x00\x13\x70\x91\x00\x00\x00\x00\x00\x00\x00\x00\x47\x78')
    (10925856, [39, 0, 38, 86, 22, 0, 19, 112, 145, 0, 0, 0, 0, 0, 0, 0, 0, 71, 120])
    >>> unpack_msg('\x00\xA6\xB7\x20')
    (10925856, [])
    """
    address = unpack(ADDRESS_FMT, message[:4])[0]
    data = [unpack('B', bytes({c}))[0] for c in message[4:]]
    return address, data


class Counter_m206:
    def __init__ (self, host,port,timeout=10, debug=False):
        self.port=port
        self.host=host
        self.timeout=timeout
        self.debug = debug
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))

    def decode(self, ch):
        bit = bin(ord(ch))[2:].zfill(8)[1:]
        return chr(int(bit, 2))

    def readSocket(self, addr,msg):
        self.socket.sendall(pack_msg(addr,msg))
        buffer = ''
        raw_buffer = []
        _data  = b''
        decoded = ''
        try:
            while True:
                """Признаком конца пакета служит отсутствие передачи на линии в течение  времени, 
                    необходимого  для передачи 5-6 байт, после окончания передачи стоп-бита последнего байта.
                    https://www.incotexcom.ru/files/em/docs/mercury-protocol-obmena-1.pdf"""
                try:
                    self.socket.settimeout(5) 
                    _data = self.socket.recv(1)
                    if _data:
                        raw_buffer.append(_data)
                        if self.debug:
                            print ('<< response', pretty_hex(_data),_data)
                        buffer += self.decode(_data)
                except:
                    break
            if self.debug:
                print ('<< response', pretty_hex(buffer),buffer)
            devaddr, decoded = unpack_msg(b''.join(raw_buffer))

        except Exception as error:
            print('Read data error:', error)
            exc_type, exc_value, exc_tb = sys.exc_info()
            tbe = traceback.TracebackException(
                exc_type, exc_value, exc_tb,
            )
            print(''.join(tbe.format()))

            print('\nexception only:')
            print(''.join(tbe.format_exception_only()))
    
        self.socket.settimeout(None)
        return decoded
   
    def display_counter_val(self, addr, cmd=0x27):
        """Энергия по тарифам"""
        data = self.readSocket( addr, cmd)
        return digitized_triple(data)

    def display_counter_vip(self, addr, cmd=0x63):
        """V I P"""
        data = self.readSocket( addr, cmd)
        voltage = digitize(data[1:3]) / 10.
        current = digitize(data[3:5]) / 100.
        power = digitize(data[5:8]) / 1000.
        return [voltage, current, power]
        


PORT = 5050
HOST = '10.137.146.41' # '10.137.154.143'
TIMEOUT = 10
ADDRESS = '38030255' #'000013'
PARAM=0x63



sock=Counter_m206(HOST,PORT,TIMEOUT)

ret=sock.display_counter_val(ADDRESS)

v,i,p=sock.display_counter_vip(ADDRESS)

print(ret)
print("{}V {}A {}kWh ".format(v,i,p))
         