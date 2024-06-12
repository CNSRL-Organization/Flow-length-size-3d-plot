import numpy as np
import plotly.graph_objs as go
import matplotlib.pyplot as plt
import pandas as pd
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.contrib.igmp import IGMP
from scapy.utils import PcapWriter
import numpy as np
from collections import Counter
import matplotlib.pyplot as plt
import csv
import pandas as pd
import plotly.graph_objects as go
import os
from datetime import datetime
from tqdm import tqdm
import argparse

class PcapParser:
    def __init__(self, pcap_fp, time_interval, csv_path):
        self.pcap_fp = pcap_fp
        self.time_interval = time_interval
        self.csv_path = csv_path
        self.sip_dict = Counter()
        self.dip_dict = Counter()
        self.start_time = None
        
        
    ###### Get the timestamp of the first packet in the pcap file
    def get_pkt_ts(self):
        pkt = rdpcap(self.pcap_fp, 1)  # read 1st pkt
        return float(pkt[0].time)

    def write_csv(self, pcap_name, current_time):
        fieldnames = ['IP', 'Flow len', 'Flow size']
        folder = ['Src', 'Dst']
        ### define csv file header
        for i in folder:
            os.makedirs(os.path.join(self.csv_path, pcap_name, i, f'Obs_{self.time_interval}s'), exist_ok=True)
        
        ### Save sip dict to csv file
        with open(os.path.join(self.csv_path, pcap_name, folder[0], f'Obs_{self.time_interval}s', f'{current_time}s.csv'), 'w') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            for key, value in self.sip_dict.items():
                writer.writerow({'IP': key, 'Flow len': value['flow_len'], 'Flow size': value['flow_size']})
                
        ### Save dip dict to csv file
        with open(os.path.join(self.csv_path, pcap_name, folder[1], f'Obs_{self.time_interval}s', f'{current_time}s.csv'), 'w') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            for key, value in self.dip_dict.items():
                writer.writerow({'IP': key, 'Flow len': value['flow_len'], 'Flow size': value['flow_size']})

    def extract_pkt_info(self, packet, pcap_name):
        if IP in packet:
            pkt_time = float(packet.time)
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            ### ip_dict data structure ###
            # {ip_src: {'flow_len': 1, 'flow_size': packet[IP].len}}
            
            ### Check if exceed the observation time ###

            if (pkt_time - self.start_time) < self.time_interval:
                if ip_src in self.sip_dict:
                    ### IP src exists in the dict ###
                    ### Update the flow length and size ###
                    self.sip_dict[ip_src]['flow_len'] += 1
                    self.sip_dict[ip_src]['flow_size'] += packet[IP].len
                else:
                    ## IP src does not exist in the dict ###
                    ## Add the IP src to the dict ###
                    self.sip_dict[ip_src] = {'flow_len': 1, 'flow_size': packet[IP].len}

                if ip_dst in self.dip_dict:
                    self.dip_dict[ip_dst]['flow_len'] += 1
                    self.dip_dict[ip_dst]['flow_size'] += packet[IP].len
                else:
                    self.dip_dict[ip_dst] = {'flow_len': 1, 'flow_size': packet[IP].len}
            else:
                print(f"Observation Interval: from {self.start_time} to {pkt_time}")
                current_time = float(packet.time)
                self.write_csv(pcap_name, current_time)
                self.start_time = current_time
                self.sip_dict.clear()
                self.dip_dict.clear()

    def pkt_handler(self, packet):
        pcap_name = os.path.basename(self.pcap_fp).split('.')[0]
        self.extract_pkt_info(packet, pcap_name)

    ### Get top 200 flow len and size #####
    ### Reason of merely using 200 since the data is heavy tail distribution ####
    ### Contain lot of flows with small size and length which take heavy burden for ploting ####
    def ori_get_flow_size(data):
        len_df =  pd.DataFrame(Counter(data['flow len']).most_common(200), columns=['Flow len', 'Count'])
        size_df = pd.DataFrame(Counter(data['flow size']).most_common(200), columns=['Flow size', 'Count'])
        return len_df , size_df

    def get_flow_size(self, data):
        len_df = pd.DataFrame(
            sorted(Counter(data['flow len']).items(), key=lambda x: x[0]), columns=['Flow len', 'Count']
        )
        size_df = pd.DataFrame(
            sorted(Counter(data['flow size']).items(), key=lambda x: x[0]), columns=['Flow size', 'Count']
        )
        return len_df, size_df
    ### Get flow count and index ####

    ## example for flow size,
    ### index_df data structure ###
    # | 1st obs time flow len | 2nd obs time flow len | 3rd obs time flow len | ...
    # | 32                   | 1500                   | 1500                 | ...
    # | 64                  | 1378                     | 1378                   | ...

    ### count_df data structure ###
    # | 1st obs time count | 2nd obs time count | 3rd obs time count | ...
    # | 4843               | 3136                  | 3198           | ...
    # | 963               | 901                  | 867
    def get_flow_count_index(self, df):
        count_df = pd.DataFrame()
        index_df = pd.DataFrame()    
        for i in range(len(df.columns) // 2):
            count_df = pd.concat([count_df, df.iloc[:, i*2+1]], axis=1)
            index_df = pd.concat([index_df, df.iloc[:, i*2]], axis=1)
        return count_df, index_df
    
    
    def process_results(self, pcap_name):
        flow_len_df, flow_size_df = pd.DataFrame(), pd.DataFrame()
        fp = os.path.join(self.csv_path, pcap_name)
        for folder in os.listdir(fp):  # src or dst
            if (folder.startswith('Src') or folder.startswith('Dst')) and os.path.isdir(os.path.join(fp, folder)):
                for subfolder in os.listdir(os.path.join(fp, folder)):  # obs interval
                    if subfolder.startswith('Obs'):
                        obs_itl = subfolder.split('_')[1]
                        file_list = sorted(os.listdir(os.path.join(fp, folder, subfolder)))
                        print('Processing:', folder, subfolder)
                        for file in file_list:
                            data = pd.read_csv(os.path.join(fp, folder, subfolder, file),
                                            header=None, usecols=[1, 2])  # only load flow size and flow len
                            data = data.rename(columns={1: 'flow len', 2: 'flow size'})
                            flow_len_df = pd.concat([flow_len_df, self.get_flow_size(data)[0]], axis=1)
                            flow_size_df = pd.concat([flow_size_df, self.get_flow_size(data)[1]], axis=1)
                            
                        flow_len_count_df, flow_len_index_df = self.get_flow_count_index(flow_len_df)
                        flow_size_count_df, flow_size_index_df = self.get_flow_count_index(flow_size_df)
                        
                        os.makedirs(os.path.join(fp, '3d plot', folder, f'Obs_{obs_itl}'), exist_ok=True)
                        flow_len_count_df.to_csv(os.path.join(fp, '3d plot', folder, f'Obs_{obs_itl}', 'flow_len_count.csv'))
                        flow_len_index_df.to_csv(os.path.join(fp, '3d plot', folder, f'Obs_{obs_itl}', 'flow_len_index.csv'))
                        flow_size_count_df.to_csv(os.path.join(fp, '3d plot', folder, f'Obs_{obs_itl}', 'flow_size_count.csv'))
                        flow_size_index_df.to_csv(os.path.join(fp, '3d plot', folder, f'Obs_{obs_itl}', 'flow_size_index.csv'))
    def parse_pcap(self):
        pcap_name = os.path.basename(self.pcap_fp).split('.')[0]
        ts = self.get_pkt_ts()
        ts_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        print(f'Pcap file: {pcap_name} 1st pkt timestamp: {ts_str}')

        self.start_time = ts
        
        
        ##### abdoned method #####
        # Determine the number of packets in the pcap file
        # Increase memeory usage, abandon this method
        # num_packets = sum(1 for _ in rdpcap(self.pcap_fp))
        # with tqdm(total=num_packets, desc='Parsing packets') as pbar:
        ##### abdoned method #####
        
        
        
        ### Using offline mode to read pcap file ###
        ### wihout storing packets in memory ###
        sniff(offline=self.pcap_fp, prn=self.pkt_handler, store=0)
        self.process_results(pcap_name)

def main(pcap_fp, time_interval, csv_path):
    parser = PcapParser(pcap_fp, time_interval, csv_path)
    parser.parse_pcap()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Parse PCAP file and analyze traffic in specified time intervals.')
    parser.add_argument('-fp', '--file_path', type=str, required=True, help='The path to the PCAP file')
    parser.add_argument('-t', '--time_interval', type=int, required=True, help='Time interval in seconds for analysis')
    parser.add_argument('-cp', '--csv_path', type=str, required=True, help='The path to save CSV files')
    
    args = parser.parse_args()
    main(args.file_path, args.time_interval, args.csv_path)
