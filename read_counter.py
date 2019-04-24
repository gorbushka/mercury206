#!/usr/bin/python
# coding: utf-8
# fork https://github.com/n0l/Mercury_remote/blob/master/get_data_python3.py
# fork https://github.com/sergray/energy-meter-mercury206
# protocol https://www.incotexcom.ru/files/em/docs/mercury-protocol-obmena-1.pdf
# Semikin@powernet 2019
import sys
sys.path.append('/home/gorbushka/mercury206/mercury206/')
from mercury206 import Counter


PORT = 5050
HOST = '10.137.146.41' # '10.137.154.143'
TIMEOUT = 10
ADDRESS = '38030255' #'000013'



sock=Counter_m206(HOST,PORT,TIMEOUT)

ret=sock.display_counter_val(ADDRESS)

v,i,p=sock.display_counter_vip(ADDRESS)

print(ret)
print("{}V {}A {}kWh ".format(v,i,p))
         
