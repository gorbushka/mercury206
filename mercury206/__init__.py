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

class Counter_m206:
    def __init__ (self, host,port,timeout=10, debug=False):
        self.port=port
        self.host=host
        self.timeout=timeout
        self.debug = debug
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        self.ADDRESS_FMT = '!I'

    def upper_hex(self, byte):
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


    def pretty_hex(self,byte_string):
        r"""
        >>> pretty_hex('Python')
        '50 79 74 68 6F 6E'
        >>> pretty_hex('\x00\xa1\xb2')
        '00 A1 B2'
        >>> pretty_hex([1, 2, 3, 5, 8, 13])
        '01 02 03 05 08 0D'
        """
        return ' '.join(self.upper_hex(c) for c in byte_string)


    def digitize(self, byte_string):
        r"""
        >>> digitize('\x00\x12\x34')
        1234
        """
        str_num = ''.join(self.upper_hex(b) for b in byte_string)
        return int(str_num)


    def digitized_triple(self, data):
        r"""
        >>> digitized_triple('\x01\x23\x45\x67\x89' * 3)
        [234567.89, 12345.67, 890123.45]
        """
        return [self.digitize(data[i:i+4]) / 100.0 for i in range(1, 13, 4)]

    def crc16(self, data):
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


    def pack_msg(self, address,command):
        address=int(address)
        if isinstance(address, int):
            data = pack(self.ADDRESS_FMT, address)
        else:
            pad_len = len(address) % 4
            data = '\x00' * pad_len + address
        data += pack('B', command)
        msg = self.crc16(data)
        return msg 

    def unpack_msg(self, message):
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
        address = unpack(self.ADDRESS_FMT, message[:4])[0]
        data = [unpack('B', bytes({c}))[0] for c in message[4:]]
        return address, data

    def decode(self, ch):
        bit = bin(ord(ch))[2:].zfill(8)[1:]
        return chr(int(bit, 2))

    def readSocket(self, addr,msg):
        self.socket.sendall(self.pack_msg(addr,msg))
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
                            print ('<< response', self.pretty_hex(_data),_data)
                        buffer += self.decode(_data)
                except:
                    break
            if self.debug:
                print ('<< response', self.pretty_hex(buffer),buffer)
            devaddr, decoded = self.unpack_msg(b''.join(raw_buffer))

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
        return self.digitized_triple(data)

    def display_counter_vip(self, addr, cmd=0x63):
        """V I P"""
        data = self.readSocket( addr, cmd)
        voltage = self.digitize(data[1:3]) / 10.
        current = self.digitize(data[3:5]) / 100.
        power = self.digitize(data[5:8]) / 1000.
        return [voltage, current, power]
        


