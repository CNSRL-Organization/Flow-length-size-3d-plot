import numpy as np
import plotly.graph_objs as go
import matplotlib.pyplot as plt
import pandas as pd
from scapy.all import *
import numpy as np
from collections import Counter
import matplotlib.pyplot as plt
import csv
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
import matplotlib.colors as mcolors
import argparse

class Pcap3DPlotter:
    def __init__(self,csv_path, k=5000, obs=10, data_type='src'):
        self.csv_path = csv_path
        self.k = k
        self.obs = obs
        self.d_type = data_type
        self.src_flow_len_count_df = pd.DataFrame()
        self.src_flow_len_index_df = pd.DataFrame()
        self.src_flow_size_count_df = pd.DataFrame()
        self.src_flow_size_index_df = pd.DataFrame()
        self.dst_flow_len_count_df = pd.DataFrame()
        self.dst_flow_len_index_df = pd.DataFrame()
        self.dst_flow_size_count_df = pd.DataFrame()
        self.dst_flow_size_index_df = pd.DataFrame()


    def load_data(self, obs):
        base_path_src = os.path.join(self.csv_path, '3d plot', 'Src', f'Obs_{obs}s')
        base_path_dst = os.path.join(self.csv_path, '3d plot', 'Dst', f'Obs_{obs}s')
        print(base_path_src)
        self.src_flow_len_count_df = pd.read_csv(os.path.join(base_path_src, 'flow_len_count.csv')).drop(columns=['Unnamed: 0'])
        self.src_flow_len_index_df = pd.read_csv(os.path.join(base_path_src, 'flow_len_index.csv')).drop(columns=['Unnamed: 0'])
        self.src_flow_size_count_df = pd.read_csv(os.path.join(base_path_src, 'flow_size_count.csv')).drop(columns=['Unnamed: 0'])
        self.src_flow_size_index_df = pd.read_csv(os.path.join(base_path_src, 'flow_size_index.csv')).drop(columns=['Unnamed: 0'])
        self.dst_flow_len_count_df = pd.read_csv(os.path.join(base_path_dst, 'flow_len_count.csv')).drop(columns=['Unnamed: 0'])
        self.dst_flow_len_index_df = pd.read_csv(os.path.join(base_path_dst, 'flow_len_index.csv')).drop(columns=['Unnamed: 0'])
        self.dst_flow_size_count_df = pd.read_csv(os.path.join(base_path_dst, 'flow_size_count.csv')).drop(columns=['Unnamed: 0'])
        self.dst_flow_size_index_df = pd.read_csv(os.path.join(base_path_dst, 'flow_size_index.csv')).drop(columns=['Unnamed: 0'])


    def create_colorscale(self, start_rgb, end_rgb, n):
        return [[i/(n-1), mcolors.to_hex((start_rgb + i*(end_rgb - start_rgb)/(n-1)).clip(0,1))]
                for i in range(n)]

    def plot_3d(self, plot_df, plot_df2, title, output_filename, yaxis_name):
        def fill_na_with_median(row):
            median_val = row.median()
            return row.fillna(median_val)
        ### z values ###
        plot_df = plot_df.fillna(0)
        log_plot_df = np.log10(plot_df + 1 )
        ### y values ###
        plot_df2 = plot_df2.apply(fill_na_with_median, axis=1)
        
        
        
        start_rgb = np.array([173, 216, 230])/255  # lightblue
        end_rgb = np.array([0, 0, 139])/255        # darkblue
        custom_colorscale = self.create_colorscale(start_rgb, end_rgb, 200)
        
        ## same path as the csv files
        out_path = os.path.join(self.csv_path, '3d plot', 'Output')
        os.makedirs(out_path, exist_ok=True)
        output_filename = os.path.join(out_path, output_filename)

        fig = go.Figure(data=[go.Surface(y=plot_df2.values, z=log_plot_df.values, colorscale=custom_colorscale,
                                        colorbar=dict(
                                            title="Flow Count (log scale)",
                                            tickvals=[0, 1, 2, 3, 4, 5],
                                            ticktext=["1", "10", "100", "1K", "10K", "100K"],
                                            lenmode="fraction",
                                        len=0.75,
                                            xpad=40
                                        ))])
        fig.update_layout(title=title, autosize=False,
                        width=1000, height=1000,
                        margin=dict(l=60, r=50, b=60, t=80))
        fig.update_layout(scene=dict(xaxis_title='x: Time Slot',
                                    yaxis_title='y: Flow {}'.format(yaxis_name),
                                    zaxis_title='z: Flow Count',
                                    zaxis = dict(
                                        tickvals=[0, 1, 2, 3, 4, 5],
                                        ticktext = ["10^0", "10^1", "10^2", "10^3", "10^4", "10^5"],
                                    )
                                    ))
        
        
        fig.update_layout(scene=dict(
            yaxis=dict(range=[0, self.k]))
        )
        fig.write_html(output_filename)
        # fig.show() not showing 

    def plot_flow_len(self, d_type='src'):
        if d_type == 'src':
            self.plot_3d(self.src_flow_len_count_df,
                        self.src_flow_len_index_df, 
                        'Flow count with flow length perspective', 
                        f'./flow_len_{d_type}_range_{self.k}_obs_{self.obs}s.html',
                        'Length')
        elif d_type == 'dst':
            self.plot_3d(self.dst_flow_len_count_df,
                        self.dst_flow_len_index_df,
                        'Flow count with flow length perspective',
                        f'./_flow_len_{d_type}_range_{self.k}_obs_{self.obs}s.html',
                        'Length')
        else:
            raise ValueError('Invalid data type. Choose either src or dst')

    def plot_flow_size(self, d_type='src'):
        if d_type =='src':
            self.plot_3d(self.src_flow_size_count_df,
                        self.src_flow_size_index_df, 
                        'Flow count with flow size perspective', 
                        f'./flow_size_{d_type}_range_{self.k}_obs_{self.obs}s.html',
                        'Size')
        elif d_type == 'dst':
            self.plot_3d(self.dst_flow_size_count_df, 
                        self.dst_flow_size_index_df,
                        'Flow count with flow size perspective',
                        f'./flow_size_{d_type}__range_{self.k}_obs_{self.obs}s.html',
                        'Size')
        else:
            raise ValueError('Invalid data type. Choose either src or dst')
        

    def process_and_plot(self):
        self.load_data(obs=self.obs)
        self.plot_flow_len()
        self.plot_flow_size()

def main(csv_path, k, obs, data_type):
    plotter = Pcap3DPlotter(csv_path, k, obs, data_type)
    plotter.process_and_plot()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Plot 3D graphs for flow length and size.')
    
    parser.add_argument('-cp', '--csv_path', type=str, required=True, help='Path to the csv files')
    # parser.add_argument('-pn', '--pcap_name', type=str, required=True, help='Name of the pcap file without extension')
    parser.add_argument('-k', type=int, default=5000, help='Y-axis range for the plots')
    parser.add_argument('-dt', '--data_type', type=str, default='src', help='Data type: src or dst')
    parser.add_argument('-obs', type=int, default=20, help='Observation interval in seconds')
    args = parser.parse_args()
    main(args.csv_path, args.k ,args.obs, args.data_type)
