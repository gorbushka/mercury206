#!/usr/bin/python3
# coding: utf-8
#https://github.com/adubkov/py-zabbix
from pyzabbix import ZabbixMetric, ZabbixSender
import sys,time
sys.path.append('/home/gorbushka/mercury/m206/mercury206')
from mercury206 import Counter_m206

#PORT = 5050
#HOST =  '172.17.119.64'
TIMEOUT = 10
#list_addresses=['38030255']
#sock=Counter_m206(HOST,PORT,TIMEOUT,False)
oarray=[]

conf_counter=[{'ip':'172.17.119.64','port':5050,'counters':['38030255']},
              {'ip':'10.99.167.237','port':4001,'counters':['38030290']}
              ]
def zabbix_packet(array):
    packet=[]
    for item in array:
        try:
            host=item[0]
            key=item[1]
            value=item[2]
            packet.append(ZabbixMetric('Mercury206_' + host,key,value))
        except Exception as error:
            print('Error array', error)
            pass
#    print(packet)
    return packet



for converter in conf_counter:
    try: 
        sock=Counter_m206(converter['ip'],converter['port'],TIMEOUT,False)
    except Exception as error:
        print('Error counter', error)
        pass
    for addr in converter['counters']:
        try:
            counter_val=sock.display_counter_val(addr)
            counter_vip=sock.display_counter_vip(addr)
        except Exception as error:
            print('Error cant connect', error)
            sys.exit(1)
        oarray.append([addr,"counter",counter_val[0]])
        oarray.append([addr,"volta",counter_vip[0]])
        oarray.append([addr,"current",counter_vip[1]])
        oarray.append([addr,"power",counter_vip[2]])
        time.sleep(1)
        

#oarray=[[addr,'CURR[A]',dict_curr['A']],
#       [addr,'CURR[B]',dict_curr['B']],
#       [addr,'CURR[C]',dict_curr['C']],
#       ]

print(oarray)

pack=zabbix_packet(oarray)
sender = ZabbixSender(use_config=True)
sender.send(pack)
