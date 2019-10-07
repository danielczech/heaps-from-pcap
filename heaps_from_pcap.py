# Assemble and display the contents of MeerKAT SPEAD2 heaps from 
# PCAP files.

import matplotlib.pyplot as plt
import numpy as np
from scapy.all import *
from scapy.utils import *
import re
import sys

NUM_PKTS = 100000

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
    pkt[7:] = np.fromstring(spead_payload[192:].decode('hex'), dtype='int8')
    return pkt

def spectra_from_heap(heap):
    # Heap shape:   (nchans per substream,  spectra per heap,   2(re, im?),  2(re im?)  )
    #               (256,                   256,                2,           2          ) 
    heap = heap.reshape((256, 256, 2, 2))
    spectra = np.sum(np.square(heap.astype(float)), axis=(3,2))  
    return spectra.T

if __name__ == '__main__':

    if(len(sys.argv) != 2):
        print('Usage: heaps_from_pcap.py PCAP_FILE')
        exit(1)

    velapcap = rdpcap(sys.argv[1])
    pkt_set = np.zeros((NUM_PKTS, 1031), dtype=int)
    pktcnt = 0
    for pkt in velapcap:
        pkt = read_spead_pkt(raw(pkt).encode('hex'))
        pkt_set[pktcnt, :] = pkt
        pktcnt += 1
        if(pktcnt>=NUM_PKTS):
            break

    unique_heaps = np.unique(pkt_set[:, 0])
    heap_set = np.zeros((len(unique_heaps), 262146), dtype=int)
    heap_spectra = np.zeros((len(unique_heaps)*256, 256))
    for i in range(0, len(unique_heaps)):
        current_heap = pkt_set[np.where(pkt_set[:,0]==unique_heaps[i])[0]]
        current_heap = current_heap[np.argsort(current_heap[:,2])]
        heap_set[i, 0] = current_heap[0, 0]
        heap_set[i, 1] = current_heap[0, 4]
        flattened_heap = np.zeros(262144)
        for j in range(current_heap.shape[0]):
            # use heap offset to re-stitch
            heap_set[i,2+current_heap[j,2]:2+current_heap[j, 2] + 1024] = current_heap[j, 7:]
            flattened_heap[current_heap[j,2]:current_heap[j, 2] + 1024] = current_heap[j, 7:]  
        heap_spectra[i*256:i*256+256, :] = spectra_from_heap(flattened_heap)
    plt.imshow(heap_spectra, aspect='auto')
    plt.show()
    plt.plot(np.sum(heap_spectra, axis = 1))
    plt.show()