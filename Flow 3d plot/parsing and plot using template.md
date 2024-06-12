# Parsing_pkt_to_flow_len_size_csv.py Using template  
## args:
### -fp -> pcap file path
### -t -> time interval
### -cp -> csv_path 

#### $python Parsing_pkt_to_flow_len_size_csv.py -fp 'your pcap file path' -t 'time interval' -cp 'csv_path'  



# plot3d.py Using template


## args:
### -cp -> csv_path
### -k ->  y axis range -> flow len or flow size
### -dt -> data type -> src or dst 
### -obs -> observation time interval


#### python .\plot3d.py -cp .\data_test\test_00002_20210413230320\ -k 2000 -dt dst -obs 10  