from scapy.all import *

# Flag 
FIN=0x01
RST=0x04

def rst_forward(pkt):
    
    # get payload length
    try:
        payload_len = len(pkt[TCP].Raw)
    except:
        payload_len = 1    
    # make flag packet
    flag_packet = pkt[Ether] / pkt[IP] / TCP(dport=pkt[TCP].dport,sport=pkt[TCP].sport,
                  seq = pkt[TCP].seq + payload_len,flags= RST)
    print "This it sparta"
    # send packet
    sendp(flag_packet)
    
def rst_backward(pkt):

    # get payload length
    try:
        payload_len = len(pkt[TCP].Raw)
    except:
        payload_len = 1
    # make flag packet
    flag_packet = Ether( dst=pkt[Ether].src, src=pkt[Ether].dst) / IP(dst=pkt[IP].src, src=pkt[IP].dst) / TCP(dport=pkt[TCP].sport,sport=pkt[TCP].dport,
                  seq=pkt[TCP].ack,ack=pkt[TCP].seq + payload_len,flags= RST) # RST flag
    # send packet
    sendp(flag_packet)

def fin_backward(pkt):

    # get payload length
    try:
        payload_len = len(pkt[TCP].Raw)
    except:
        payload_len = 1
    # make flag packet
    flag_packet = Ether( dst=pkt[Ether].src, src=pkt[Ether].dst) / IP(dst=pkt[IP].src, src=pkt[IP].dst) / TCP(dport=pkt[TCP].sport,sport=pkt[TCP].dport,
               	  seq=pkt[TCP].ack,ack=pkt[TCP].seq + payload_len,flags= FIN) # FIN flag
    # add some message in FIN flag packet "blocked"
    message = "You shall not pass\r\n"
    flag_packet = flag_packet / Raw(load=message)
    print "HTTP FIN sended"
    #send packet
    sendp(flag_packet)

def callback(pkt):

    payload = pkt.payload

    #if RST, FIN in tcp, ignore pkt
    if pkt[TCP].flags & RST or pkt[TCP].flags & FIN:
            return
    #if HTTP packet
    if "HTTP" in str(pkt) and str(pkt[Raw]).split()[0]:
        rst_forward(pkt)
        fin_backward(pkt)
    #if TCP packet
    else:
        rst_forward(pkt)
        rst_backward(pkt)    

if __name__ == "__main__":
    sniff(prn= callback, filter= "tcp")

