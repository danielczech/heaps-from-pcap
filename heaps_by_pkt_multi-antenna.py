# Assemble and display the contents of MeerKAT SPEAD2 heaps from 
# PCAP files. This version assembles packet by packet. 

#import matplotlib.pyplot as plt
import numpy as np
from scapy.all import *
from scapy.utils import *
import re
import sys

def read_spead_pkt(hexraw):
    """
    Extract spead payload and header information from MeerKAT multicast 
    SPEAD2 packets.

    Example of a MeerKAT spead2 packet:

    spead header:   53 04 02 06 00 00 00 0b 
            Magic number:       53
            Version:            04
            Item pointer width: 02 (bytes)
            Heap addr width:    06 (bytes)
            Reserved:           00 00
            Number of items:    00 0b (ie 11 in decimal)

    heap ID:        80 01 -- 2c 97 78 0c 00 00  8 -> immediate addr bit
    heap size:      80 02 -- 00 00 00 04 00 00
    heap offset:    80 03 -- 00 00 00 03 80 00
    payload size:   80 04 -- 00 00 00 00 04 00

    timestamp:      96 00 -- 2c 97 78 00 00 00  9 -> immediate addr bit
    feng ID:        c1 01 -- 00 00 00 00 00 00  c -> immediate addr bit
    frequency:      c1 03 -- 00 00 00 00 0c 00

    feng raw:       43 00 -- 00 00 00 00 00 00 
                    80 00 -- 00 00 00 00 00 00      Blank placeholders
                    80 00 -- 00 00 00 00 00 00 
                    80 00 -- 00 00 00 00 00 00 

                    1024 bytes of payload follow.
    """
    spead_payload = re.search('53.*$', hexraw).group(0)
    pkt = np.zeros(1031)
    pkt[0] =  int(spead_payload[20:32], 16)     # heap_ID
    pkt[1] =  int(spead_payload[36:48], 16)     # heap_size
    pkt[2] =  int(spead_payload[52:64], 16)     # heap_offset
    pkt[3] =  int(spead_payload[68:80], 16)     # payload_size
    pkt[4] =  int(spead_payload[84:96], 16)     # timestamp
    pkt[5] =  int(spead_payload[100:112], 16)   # feng_ID
    pkt[6] =  int(spead_payload[116:128], 16)   # frequency
    if(len(np.fromstring(spead_payload[192:].decode('hex'), dtype='int8'))<1024):
        print 'problem pkt'
        return pkt
    else:
        pkt[7:] = np.fromstring(spead_payload[192:].decode('hex'), dtype='int8')
        return pkt

def spectra_from_heap(heap):
    # Heap shape:   (nchans per substream,  spectra per heap,   2(re, im?),  2(re im?)  )
    #               (256,                   256,                2,           2          ) 
    heap = heap.reshape((256, 256, 2, 2))
    spectra = np.sum(np.square(heap.astype(float)), axis=(3,2))  
    return spectra.T

def spectra_from_antenna(pkt_set):
    # Heap shape:   (nchans per substream,  spectra per heap,   2(re, im?),  2(re im?)  )
    #               (256,                   256,                2,           2          ) 
    unique_heaps = np.unique(pkt_set[:, 0])
    heap_set = np.zeros((len(unique_heaps), 262146), dtype=int)
    heap_spectra = np.zeros((len(unique_heaps)*256, 256))
    for i in range(0, len(unique_heaps)):
        current_heap = pkt_set[np.where(pkt_set[:,0]==unique_heaps[i])[0]]
        current_heap = current_heap[np.argsort(current_heap[:,2])]
        for j in range(current_heap.shape[0]):        
            current_ts = current_heap[j, 7:].reshape((256, 2, 2))
            current_ts = np.sum(np.square(current_ts.astype(float)), axis=(2,1))
            heap_spectra[256*i:256*i+256, current_heap[j, 2]/1024] = current_ts
    return heap_spectra


if __name__ == '__main__':

    if(len(sys.argv) != 2):
        print('Usage: heaps_by_pkt.py PCAP_FILE')
        exit(1)

    source_IPs = ['10.100.6.5', '10.100.6.21', '10.100.6.41', '10.100.6.49']

    velapcap = rdpcap(sys.argv[1])
    pkt_set = np.zeros((35000, 1031*len(source_IPs)), dtype=int)
    pktcnts = np.zeros(len(source_IPs), dtype=int)

    for pkt in velapcap:
        try:
            pktsetno = int(source_IPs.index(pkt[IP].src))
        except(IndexError):
            print pktcnts
            print 'issue'

        pkt = read_spead_pkt(raw(pkt).encode('hex'))

        pkt_set[pktcnts[pktsetno], pktsetno*1031:pktsetno*1031+1031] = pkt
        pktcnts[pktsetno] += 1
        if(pktcnts[pktsetno]>35000):
            continue

    for i in range(0,len(source_IPs)):
        heap_spectra = spectra_from_antenna(pkt_set[:,i*1031:i*1031+1031])
        np.save('heap_spectra_'+str(i)+'.npy', heap_spectra)


    # plt.imshow(heap_spectra, aspect='auto')
    # plt.show()
    # plt.plot(np.sum(heap_spectra, axis = 1))
    # plt.show()
    # ave_sum = np.convolve(np.sum(heap_spectra, axis = 1),np.ones(20)*0.05, mode='valid')
    # plt.plot(ave_sum)
    # plt.show()

    # np.save('heap_spectra.npy', heap_spectra)
