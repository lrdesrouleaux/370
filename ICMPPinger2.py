import os       # Needed for process ID
import sys      # Needed to check if sys.platform is darwin (kernel)
import struct   # Needed to unpack the struct that is the receieved packet
import time     # Needed for timing RTT
import select   # Needed for monitoring sockets
import socket   # Used for manipulating the socket
import argparse #used for passing arguments
ICMP_ECHO_REQUEST_RATE = 8      # Type must be set to 0
ap = argparse.ArgumentParser()
ap.add_argument("-d", "--destination",default="127.0.0.1"
 ,required=False,
	help="address that will be pinged")
ap.add_argument("-n", "--number",default=256
 ,required=False,
	help="number of ICMP pings that will be sent")
args = vars(ap.parse_args())

# This function returns the time delay between sending and receiving a single ping.


def perform_one_ping(destination_add, timeout):
    # Translates protocol name into a constant to be passed as an (optional) argument to the socket function
    icmp_ping = socket.getprotobyname("icmp")
    # Creates a new socket (family = AF_INET, socket type = raw, protocol number = icmp_ping)
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_ping)
    # Get the process id
    myID = os.getpid() & 0xFFFF
    # Calls function to send a single ping
    sendsingle_icmpping(mySocket, destination_add, myID)
    # Calls function to receive a single ping (delay hold, # of bits, time, etc.)
    delay = receivesingle_icmpping(mySocket, myID, timeout, destination_add)
    mySocket.close()           # Closes the socket
    return delay               # Returns the delay struct with data from the sent/received ping

# This function receives a single ping.


def receivesingle_icmpping(mySocket, ID, timeout, destAddr):
    # Variables to keep track of RTT and and number of trips
    global roundTrip_min, roundTrip_max, roundTrip_sum, roundTrip_cnt
    # Time remaining to receive packet
    timeRemain = timeout
    while 1:                                                    # Loops until out of time
        # Get start time to receive ping
        startedSelect = time.time()
        # Interface system call, waits until ready for reading, and gets timeout, returns a triple of list objects
        arr = select.select([mySocket], [], [], timeRemain)
        # Gets total time it took to receive ping
        howLongInSelect = (time.time() - startedSelect)
        # Checks if the returned array is empty, it will be empty if the timeout was reached
        if arr[0] == []:
            # Print message indicating it took too long
            return "Request timed out."
        # Gets the time that the ping is received
        timeReceived = time.time()
        # Bits from socket are stored in received_Packet, and the address of the socket stored in addr
        received_Packet, addr = mySocket.recvfrom(1024)
        # Unpack the struct from the packet, "bbHHh" is the variable type for each, ex: b = unsigned char, H = unsigned short, h = short
        type, code, checksum, id, seq = struct.unpack(
            'bbHHh', received_Packet[20:28])
        if type != 0:                                                       # Type should be 0
            return 'expected type=0, but got {}'.format(type)
        if code != 0:                                                       # Code should be 0
            return 'expected code=0, but got {}'.format(code)
        if ID != id:                                                        # If the IDs do not match
            return 'expected id={}, but got {}'.format(ID, id)
        # Gets the time the ping was sent
        trans_time, = struct.unpack('d', received_Packet[28:])
        # Calculates round trip time
        roundTrip = (timeReceived - trans_time) * 1000
        # Increase number of trips by 1
        roundTrip_cnt += 1
        # Adds current RTT to sum
        roundTrip_sum += roundTrip
        # Gets the current minimum round trip time
        roundTrip_min = min(roundTrip_min, roundTrip)
        # Gets the current maximum round trip time
        roundTrip_max = max(roundTrip_max, roundTrip)
        # Unpacks the first 20 bits
        ip_pkt_head = struct.unpack('!BBHHHBBH4s4s', received_Packet[:20])
        # Gets time to live of request
        ttl = ip_pkt_head[5]
        # Gets the socket address
        saddr = socket.inet_ntoa(ip_pkt_head[8])
        # Gets the length of packet (not including time bits)
        length = len(received_Packet) - 20
        # Returns multiple variables
        return '{} bytes from {}: icmp_seq={} ttl={} time={:.3f} ms'.format(length, saddr, seq, ttl, roundTrip)
        timeRemain = timeRemain - howLongInSelect       # Gets the time remaining
        if timeRemain <= 0:                             # If the time reaches 0 it has taken too long
            return "Request timed out."


# The checksum function used to evaluate the checksum.
# The answer of the checksum calculation is returned.
def checksum(str):
    count_sum = 0                           # Set count sum to 0
    countTo = (len(str) / 2) * 2            # Get length in bits
    count = 0
    while count < countTo:      # While there are still bits to go through
        # Returns the current bit, Ord returns an integer that represents the unicode symbol
        thisVal = ord(str[count + 1]) * 256 + ord(str[count])
        # Adds bit to the count sum
        count_sum = count_sum + thisVal
        # Bitwise and operation to check for overflow
        count_sum = count_sum & 0xffffffff
        # Move to next bit
        count = count + 2
    if countTo < len(str):                                  # If more bits in the string
        count_sum = count_sum + ord(str[len(str) - 1])      # Add the last bit
        # Bitwise and operation to check for overflow
        count_sum = count_sum & 0xffffffff
    # Shifts the bits right 16 places and check for overflow
    count_sum = (count_sum >> 16) + (count_sum & 0xffff)
    # Add to count sum and count sum shifted 16 right
    count_sum = count_sum + (count_sum >> 16)
    # Returns the complement of count sum
    calc = ~count_sum
    # Check overflow and sign again
    calc = calc & 0xffff
    # Does a bitwise or on the first and last 8 bits?
    calc = calc >> 8 | (calc << 8 & 0xff00)
    return calc                                     # Return count checkSum


# This function sends a single ping.
def sendsingle_icmpping(mySocket, destination_add, ID):
    count_checksum = 0
    # Pack the struct that is the packet head
    pkt_head = struct.pack(
        "bbHHh", ICMP_ECHO_REQUEST_RATE, 0, count_checksum, ID, 1)
    # Pack the time into a struct
    data = struct.pack("d", time.time())
    # Get the checksum
    count_checksum = checksum(pkt_head + data)
    # Check the platform of the system (like the kernel)
    if sys.platform == 'darwin':
        # Convert 16-bit positive integers from host to network byte order with and get last 8 bits
        count_checksum = socket.htons(count_checksum) & 0xffff
    else:
        # Convert 16-bit positive integers from host to network byte order
        count_checksum = socket.htons(count_checksum)
    # Pack the struct with the new checksum
    pkt_head = struct.pack(
        "bbHHh", ICMP_ECHO_REQUEST_RATE, 0, count_checksum, ID, 1)
    # Add bits to form packet
    packet = pkt_head + data
    # Send the packet to destination
    mySocket.sendto(packet, (destination_add, 1))


# This function displays the ping statistics.
def ping(host, timeout=1):
    # Define RTT variables
    global roundTrip_min, roundTrip_max, roundTrip_sum, roundTrip_cnt
    roundTrip_min = float('+inf')       # Sets min to negative infinity
    roundTrip_max = float('-inf')       # Sets max to positive infinity
    roundTrip_sum = 0
    roundTrip_cnt = 0
    count = 0
    # Sets destination to the host name
    dest = socket.gethostbyname(host)
    # Print statement indicating destination of ping
    print("Pinging " + dest + " using Python:")
    for i in range (0,int(args["number"])):
        count += 1
        # calls function to send ping
        print (perform_one_ping(dest, timeout))
        time.sleep(1)                           # Wait one second
    # Stops when the user hits the interrupt key
    if count != 0:
        # Print and format statistics
        print '--- {} ping statistics ---'.format(host)
        print '{} packets transmitted, {} packets received, {:.1f}% packet loss'.format(count, roundTrip_cnt,
                                                                                        100.0 - roundTrip_cnt * 100.0 / count)
        if roundTrip_cnt != 0:
            print 'round-trip min/avg/max {:.3f}/{:.3f}/{:.3f} ms'.format(roundTrip_min, roundTrip_sum / roundTrip_cnt, roundTrip_max)


# Calls ping routine to the local host
ping(args["destination"])
