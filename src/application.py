"""
DATA2410 Reliable Transport Protocol (DRTP) File Transfer Application:
This is an application that uses reliable data transfer protocols.
These protocols include stop-and-wait, go-back-n, and selective-repeat.
Each of these protocols uses a different technique to ensure
that data is transferred correctly and in order over a network.
"""
import argparse
import socket
import sys
from struct import *
from collections import deque
import time

DEFAULT_IP = '127.0.0.1'               # The default ip address for server
HEADER_FORMAT = '!IIHH'                # The default header format
DEFAULT_PORT = 8088                    # The default port for server
HEADER_SIZE = 12                       # Default header size
DATA_SIZE = 1460                       # The default data size
PACKET_SIZE = HEADER_SIZE + DATA_SIZE  # Calculates packet size by adding together header and data size
WINDOW_SIZE = 5                        # The default window size for gbn and sr
TIMEOUT = 0.5                          # The default timeout for client socket
MAX_ATTEMPTS = 10                      # Maximum number of connection attempts


def create_packet(seq, ack, flags, win, data):
    """
    Description:
    Creates a packet by packing the given sequence number, acknowledgement number,
    flags, window size, and data into a binary representation.

    Args:
        seq (int): The sequence number of the packet.
        ack (int): The acknowledgement number of the packet.
        flags (int): The flags indicating packet properties.
        win (int): The window size of the packet.
        data (bytes): The data to be included in the packet.

    Returns:
        packet (bytes): The packet created by concatenating the header and data.
    """
    # Pack the header fields into a binary representation
    header = pack(HEADER_FORMAT, seq, ack, flags, win)

    # Concatenate the header and data to create the packet
    packet = header + data

    return packet


def parse_header(header):
    """
    Description:
    Parses a binary header into its individual fields.

    Args:
        header (bytes): The binary header to be parsed.

    Returns:
        header (tuple): A tuple containing the parsed fields of the header.
    """
    # Unpack the binary header into individual fields
    header = unpack(HEADER_FORMAT, header)

    return header


def parse_flags(flags):
    """
    Description:
    Parses the flags field of a packet and extracts individual flag values.

    Args:
        flags (int): The flags field of the packet.

    Returns:
        tuple: A tuple containing the parsed flag values: (syn, ack, fin, rst).
    """

    # Extract the individual flag values using bitwise AND operations
    syn = flags & (1 << 3)  # 1 << 3 = 8, synchronize
    ack = flags & (1 << 2)  # 1 << 2 = 4, acknowledge
    fin = flags & (1 << 1)  # 1 << 1 = 2, finalize
    rst = flags & (1 << 0)  # 1 << 0 = 1, reset

    return syn, ack, fin, rst


def stop_and_wait_sender(sock, file_name, address, port, test_scenario=None, ct=False):
    """
    Description:
    Implements the stop-and-wait protocol for sending packets over a socket connection.

    Args:
        sock (socket.socket): The socket object for the connection.
        file_name (str): The name of the file to be sent.
        address (str): The IP address of the receiver.
        port (int): The port number of the receiver.
        test_scenario (str, optional): The test scenario to simulate packet loss. Defaults to None.
        ct (float, optional): The timeout value in seconds. Defaults to False.
    """
    packets = []

    # Read the file passed as argument
    with open(file_name, "rb") as file:
        total_data_size = 0  # Total size of data sent
        while True:
            data = file.read(DATA_SIZE)
            if not data:
                break
            total_data_size += len(data)  # Add the size of data to total
            packets.append(data)

    # If 'ct' argument is not provided, use a fixed timeout
    if ct:
        sock.settimeout(ct)
        print(ct)
    else:
        sock.settimeout(TIMEOUT)

    count_loss = 0
    ack_received = {}  # Dictionary to track received ACKs
    packet_loss_status = {}  # Dictionary to track if a packet has been lost once
    seq_num = 1
    num_acknowledged_packets = 0
    send_time = {}  # Send time for each packet
    trans_start_time = time.time()

    print(len(packets), "packet size")

    while num_acknowledged_packets < len(packets):
        i = num_acknowledged_packets
        print(f"seq {seq_num}")

        if i == len(packets) - 1:
            packet = create_packet(seq_num, 0, 2, 0, packets[i])
            print(f"creating last packet {seq_num}")
        else:
            packet = create_packet(seq_num, 0, 0, 0, packets[i])
            print(f"creating packet {seq_num}")

        while True:
            resend_packet = False
            try:
                # Simulate packet loss
                if test_scenario == "loss" and seq_num not in packet_loss_status and seq_num % 5 == 0 and count_loss < 10:
                    packet_loss_status[seq_num] = True
                    print(f"packet nr {seq_num} lost")
                    count_loss += 1
                else:
                    if seq_num in packet_loss_status:
                        print(f"retransmitted loss packet {seq_num}")
                    print(f"sending packet nr {seq_num}")
                    sock.sendto(packet, (address, port))
                    send_time[seq_num] = time.time()  # Record send time

                ack_packet, _ = sock.recvfrom(PACKET_SIZE)
                _, ack, _, _ = parse_header(ack_packet[:HEADER_SIZE])

                if ack == seq_num and ack not in ack_received:
                    # Calculate the RTT for this packet
                    # If 'ct' argument is provided, use it to set the timeout
                    if ct and ack in send_time:
                        rtt_value = time.time() - send_time[ack]
                        print(f"rtt for packet {ack} and time {round(rtt_value, 4)}")
                        sett_rtt_value = 4 * rtt_value
                        print(f"rtt for packet {ack} and time for 4rtt {round(sett_rtt_value, 3)}")
                        sock.settimeout(sett_rtt_value)

                    ack_received[seq_num] = True  # Mark this sequence is having its ACK received
                    seq_num += 1
                    num_acknowledged_packets += 1
                    print(f"ack received for packet {ack}")
                    break

                elif ack in ack_received:
                    # If the ACK was already received before (DUPACK), resend the packet
                    print(f"Discarded out-of-order packet {ack}")

            except socket.timeout:
                # If timeout occurs, resend the packet
                resend_packet = True
                print("timeout occurs")

            if resend_packet:
                print(f"preparing to retransmit packet nr {seq_num} ")
                # Resend the packet and wait for the ACK again
                continue

    if ct:
        sock.settimeout(None)
    print("stop_and_wait finish")

    # Calculate and print the throughput
    trans_end_time = time.time()
    transfer_time = trans_end_time - trans_start_time
    total_data_size_bits = total_data_size * 8  # Convert total data size to bits
    throughput = total_data_size_bits / transfer_time / 1e6  # Throughput in bits per second
    throughput = round(throughput, 2)

    print(f"total time transferred {transfer_time}")
    print(f"total bits transferred {total_data_size_bits}")
    print(f"Throughput: {throughput} Mbps")


def stop_and_wait_receiver(sock, file_name, test_scenario=None):
    """
    Description:
    The Stop-and-Wait Receiver function for reliable data transfer.

    Args:
        sock (socket.socket): The socket that is used for communication.
        file_name (str): The name of the file that will be received.
        test_scenario (str, optional): The test scenario to be used. Defaults to None.
    """
    received_data = {}    # Dictionary to store received packet data
    expected_seq_num = 1  # The sequence number that we are expecting next
    skipped_ack = {}      # Dictionary to track skipped ACKs
    count_skipack = 0     # Counter for skipped ACKs

    while True:
        # Receive packet from the client
        packet, client_address = sock.recvfrom(PACKET_SIZE)
        # Parse the packet header
        seq, _, flags, _ = parse_header(packet[:HEADER_SIZE])
        print(f"seq{seq}")
        # Parse the packet flags
        syn, ack_flag, fin, rst = parse_flags(flags)

        # Handle received packet
        if seq == expected_seq_num and not fin:
            # Store the packet data in the dictionary, overwriting any previous data with the same sequence number
            received_data[seq] = packet[HEADER_SIZE:]
            print(f"going through seq {seq}")

            # Create ACK packet
            ack_packet = create_packet(0, seq, 4, 0, b"")
            print(f"created packet seq {seq}")

            # Simulate skipping ACK
            if test_scenario == 'skipack' and seq not in skipped_ack and seq % 5 == 0 and count_skipack < 10:
                skipped_ack[seq] = True
                print(f"skipped seq {seq}")
                count_skipack += 1
            else:
                # Send ACK packet
                sock.sendto(ack_packet, client_address)
                # Increase the expected sequence number
                expected_seq_num += 1
                print(f"sending ack for packet with seq {seq}")

        # Handle last packet
        elif seq == expected_seq_num and fin:
            # Store the packet data in the dictionary, overwriting any previous data with the same sequence number
            received_data[seq] = packet[HEADER_SIZE:]
            # Create ACK packet
            ack_packet = create_packet(0, seq, 4, 0, b"")
            print(f"going through seq for last packet {seq}")

            # Simulate skipping ACK
            if test_scenario == 'skipack' and seq not in skipped_ack and seq % 5 == 0:
                skipped_ack[seq] = True
                print(test_scenario, seq, "was skipped for seq")
            else:
                # Send ACK packet
                print(f"sending ack for packet with seq {seq}")
                sock.sendto(ack_packet, client_address)
                # Increase the expected sequence number
                expected_seq_num += 1
                print("received FIN")
                break

        # Handle duplicate packets
        elif seq < expected_seq_num and seq in received_data:
            # Create ACK packet for the duplicate packet
            ack_packet = create_packet(0, seq, 4, 0, b"")
            # Send the ACK packet
            sock.sendto(ack_packet, client_address)
            print(f"sending duplicate packet with seq {seq}")

    # Write the received data to the file
    with open(file_name, "wb") as file:
        for seq, data in sorted(received_data.items()):
            file.write(data)


def go_back_n_sender(sock, file_name, address, port, test_scenario=None, window_size=WINDOW_SIZE, ct=False):
    """
    Description:
    The Go-Back-N Sender function for reliable data transfer.

    Args:
        sock (socket.socket): The socket that is used for communication.
        file_name (str): The name of the file to be sent.
        address (str): The IP address of the receiver.
        port (int): The port number of the receiver.
        test_scenario (str, optional): The test scenario to be used. Defaults to None.
        window_size (int, optional): The size of the sender's window. Defaults to WINDOW_SIZE.
        ct (bool, optional): If True, sets the socket timeout based on the RTT. Defaults to False.
    """
    packets = []  # List to store the data packets

    # Read the file and create the data packets
    with open(file_name, "rb") as file:
        total_data_size = 0  # Total size of data sent
        while True:
            data = file.read(DATA_SIZE)  # Read DATA_SIZE bytes
            if not data:
                break
            total_data_size += len(data)  # Add the size of data to total
            packets.append(data)  # Append the data to the packets list

    # Set the socket timeout
    if ct:  # If 'rtt' argument is provided, use it
        sock.settimeout(ct)
    else:  # Otherwise, use a fixed timeout
        sock.settimeout(TIMEOUT)

    base = 1  # The sequence number of the oldest unacknowledged packet
    next_seq_num = 1  # The sequence number of the next packet to be sent
    num_acknowledged_packets = 0  # The number of acknowledged packets
    loss_packet_seq_nums = set()  # Set to store the sequence numbers of the lost packets
    send_time = {}  # Dictionary to store send time of each packet
    trans_start_time = time.time()  # The start time of the transmission
    count_loss = 0  # Counter for the number of lost packets

    # Send all packets
    while num_acknowledged_packets < len(packets):
        # Send packets within the window
        while next_seq_num < base + window_size and next_seq_num <= len(packets):
            i = next_seq_num - 1
            # If it is the last packet, set the FIN flag
            if i == len(packets) - 1:
                packet = create_packet(next_seq_num, 0, 2, 0, packets[i])
            else:
                packet = create_packet(next_seq_num, 0, 0, 0, packets[i])

            # Simulate packet loss
            if test_scenario == "loss" and next_seq_num not in loss_packet_seq_nums and next_seq_num % 5 == 0 and count_loss < 10:
                loss_packet_seq_nums.add(next_seq_num)
                print(f"packet loss  {next_seq_num}")
                count_loss += 1
            else:
                # Send packet
                if next_seq_num in loss_packet_seq_nums:
                    print(f"retransmitted loss packet {next_seq_num}")
                sock.sendto(packet, (address, port))
                send_time[next_seq_num] = time.time()  # Record send time
                print(f"Sent packet {next_seq_num}")
            next_seq_num += 1

        try:
            # Receive ACK
            ack_packet, _ = sock.recvfrom(PACKET_SIZE)
            _, ack, _, _ = parse_header(ack_packet[:HEADER_SIZE])

            # If ACK received, slide the window
            if ack >= base:
                num_acknowledged_packets += ack - base + 1
                base = ack + 1
                # Calculate the RTT for this packet, if the 'ct' argument is provided
                if ct and ack in send_time:
                    rtt_value = time.time() - send_time[ack]
                    print(f"rtt for packet {ack} and time {round(rtt_value, 4)}")
                    sett_rtt_value = 4 * rtt_value
                    print(f"rtt for packet {ack} and time for 4rtt {round(sett_rtt_value, 3)}")
                    sock.settimeout(sett_rtt_value)

        # If timeout occurs, reset the sequence number to base to retransmit all unacknowledged packets
        except socket.timeout:
            print("Timeout occurred")
            next_seq_num = base

    print("File transfer complete")

    # Calculate the throughput
    trans_end_time = time.time()
    transfer_time = trans_end_time - trans_start_time
    total_data_size_bits = total_data_size * 8  # Convert total data size to bits
    throughput = total_data_size_bits / transfer_time / 1e6  # Throughput in megabits per second
    throughput = round(throughput, 2)

    print(f"total time transferred {transfer_time}")
    print(f"total bits transferred {total_data_size_bits}")
    print(f"Throughput: {throughput} Mbps")


def go_back_n_receiver(sock, file_name, test_scenario=None, window_size=WINDOW_SIZE):
    """
    Description:
    Function to receive file from the sender using the Go-Back-N protocol.

    Args:
        sock (socket): Socket object to receive data
        file_name (str): Name of the file to be received
        test_scenario (str): Scenario to test the reliability of the protocol
        window_size (int): Window size for the sliding window protocol
    """
    expected_seq_num = 1
    max_window_size = window_size

    # Store received packets in a deque with a maximum length
    received_packets = deque(maxlen=max_window_size)
    skipped_ack_seq_nums = set()
    count_skipack = 0

    # Open the file in binary write mode
    with open(file_name, "wb") as file:
        while True:
            # Receive packet from sender
            packet, sender_addr = sock.recvfrom(PACKET_SIZE)
            # Parse the packet header
            seq_num, _, flags, win_size = parse_header(packet[:HEADER_SIZE])
            syn, ack_flag, fin, _ = parse_flags(flags)

            if seq_num == expected_seq_num and not fin:
                # Test scenario: skip ACK for specific packets
                if test_scenario == "skipack" and seq_num % 4 == 0 and seq_num not in skipped_ack_seq_nums and count_skipack < 10:
                    print(f"Skipping ACK for packet {seq_num}")
                    skipped_ack_seq_nums.add(seq_num)
                    count_skipack += 1
                else:
                    if seq_num in skipped_ack_seq_nums:
                        print(f"retransmitted ack packet {seq_num}")
                    # Append received packet to deque and send ACK
                    received_packets.append((seq_num, packet[HEADER_SIZE:]))
                    ack_packet = create_packet(0, seq_num, 0, 0, b'')
                    sock.sendto(ack_packet, sender_addr)
                    print(f"Received and acknowledged packet {seq_num}")
                    expected_seq_num += 1
                    # Write the packet to the file
                    _, data = received_packets.popleft()
                    file.write(data)

            elif seq_num == expected_seq_num and fin:
                # Append received packet to deque and send ACK
                received_packets.append((seq_num, packet[12:]))
                ack_packet = create_packet(0, seq_num, 0, 0, b'')
                sock.sendto(ack_packet, sender_addr)
                print(f"Received and acknowledged the last packet {seq_num}")

                # Write the remaining packets to the file
                while received_packets:
                    _, data = received_packets.popleft()
                    file.write(data)
                break

            elif seq_num > expected_seq_num:
                # Discard out-of-order packet
                print(f"Discarded out-of-order packet {seq_num}")
            elif seq_num < expected_seq_num:
                # Send ACK for the duplicate packet
                ack_packet = create_packet(0, seq_num, 0, 0, b'')
                sock.sendto(ack_packet, sender_addr)
                print(f"Received and acknowledged the duplicate packet {seq_num}")

    print("File transfer complete")


def selective_repeat_sender(sock, file_name, address, port, test_scenario=None, win_size=WINDOW_SIZE, rtt=False):
    """
    Description:
    Function to send file to the receiver using the Selective Repeat protocol.

    Args:
        sock (socket): Socket object to send data
        file_name (str): Name of the file to be sent
        address (str): IP address of the receiver
        port (int): Port number of the receiver
        test_scenario (str): Scenario to test the reliability of the protocol
        win_size (int): Window size for the sliding window protocol
        rtt (bool): Round-trip time measurement flag
    """
    packets = []  # List to store the data packets

    # Open the file in binary read mode
    with open(file_name, "rb") as file:
        seq_num = 1
        total_data_size = 0  # Total size of data sent

        while True:
            # Read a chunk of data from the file
            data = file.read(DATA_SIZE)
            if not data:
                break
            total_data_size += len(data)  # Add the size of data to total
            # Create a packet with the data and append it to the list of packets
            packet = create_packet(seq_num, 0, 0, 0, data)
            packets.append(packet)
            print(f"Created packet with sequence number: {seq_num}")
            seq_num += 1

    loss_packet = {}
    base = 1
    next_seq_num = 1
    window_size = win_size
    loss = False

    # If 'ct' argument is not provided, use a fixed timeout
    if rtt:
        sock.settimeout(rtt)
    else:
        sock.settimeout(TIMEOUT)

    count_loss = 0
    sent_packets = set()
    acked_packets = set()
    send_time = {}
    trans_start_time = time.time()

    while base <= len(packets):
        while next_seq_num < base + window_size and next_seq_num <= len(packets):
            if next_seq_num not in acked_packets:
                if test_scenario == "loss" and next_seq_num not in loss_packet and next_seq_num % 5 == 0 and count_loss < 10:
                    loss_packet[next_seq_num] = True
                    print(f"loss packet {next_seq_num}")
                    count_loss += 1
                    loss = True
                else:
                    sock.sendto(packets[next_seq_num - 1], (address, port))
                    sent_packets.add(next_seq_num)
                    print(f"Sent packet with sequence number: {next_seq_num}")
                    send_time[next_seq_num] = time.time()
                next_seq_num += 1

        try:
            ack_packet, _ = sock.recvfrom(PACKET_SIZE)
            _, ack, _, _ = parse_header(ack_packet[:HEADER_SIZE])

            if ack in range(base, next_seq_num):
                acked_packets.add(ack)
                print(f"Received ACK for packet with sequence number: {ack}")

                # Calculate the RTT for this packet, if the 'ct' argument is provided
                if rtt and ack in send_time:
                    rtt_value = time.time() - send_time[ack]
                    print(f"rtt for packet {ack} and time {round(rtt_value, 4)}")
                    sett_rtt_value = 4 * rtt_value
                    print(f"rtt for packet {ack} and time for 4rtt {round(sett_rtt_value, 3)}")
                    sock.settimeout(sett_rtt_value)

                while base in acked_packets:
                    base += 1
                    next_seq_num = max(base, next_seq_num)
        except socket.timeout:
            print("Timeout occurred")
            
            if loss:
                for seq_num in loss_packet:
                    if seq_num not in acked_packets:
                        sock.sendto(packets[seq_num - 1], (address, port))
                        print(f"Retransmitting packet with sequence number: {seq_num}")
                        if rtt:
                            send_time[seq_num] = time.time()  # Update send time for retransmitted packets

            for seq_num in sent_packets:
                if seq_num not in acked_packets:
                    sock.sendto(packets[seq_num - 1], (address, port))
                    print(f"Retransmitting packet with sequence number: {seq_num}")
                    if rtt:
                        send_time[seq_num] = time.time()  # Update send time for retransmitted packets

    # All packets have been acknowledged, now send the packet with the FIN flag set
    fin_packet = create_packet(seq_num, 0, 2, 0, b"")
    sock.sendto(fin_packet, (address, port))
    print("All packets sent and acknowledged, sent the packet with the FIN flag")

    # Calculate the throughput
    trans_end_time = time.time()
    transfer_time = trans_end_time - trans_start_time
    total_data_size_bits = total_data_size * 8  # Convert total data size to bits
    throughput = total_data_size_bits / transfer_time / 1e6  # Throughput in megabits per second
    throughput = round(throughput, 2)

    print(f"total time transferred {transfer_time}")
    print(f"total bits transferred {total_data_size_bits}")
    print(f"Throughput: {throughput} Mbps")


def selective_repeat_receiver(sock, file_name, test_scenario=None):
    """
    Description:
    Function to receive a file from the sender using the Selective Repeat protocol.

    Args:
        sock (socket): Socket object to receive data
        file_name (str): Name of the file to be received
        test_scenario (str): Scenario to test the reliability of the protocol
    """

    received_data = {}  # Dictionary to store received packets
    expected_seq_num = 1  # Initialize the expected sequence number
    skipack_packet = {}  # Dictionary to simulate ACK loss
    count_skipack = 0  # Counter for skipped acknowledgements

    # Open the file in binary write mode
    with open(file_name, "wb") as file:
        while True:
            # Receive a packet from the sender
            packet, add_sender = sock.recvfrom(PACKET_SIZE)

            # Parse the header of the packet
            seq, _, flags, _ = parse_header(packet[:HEADER_SIZE])
            _, _, fin, _ = parse_flags(flags)

            # If the FIN flag is set, end the file transfer
            if fin:
                print("FIN flag received, ending file transfer")
                break

            # Simulate ACK loss for testing purposes
            if test_scenario == "skipack" and seq not in skipack_packet and seq % 5 == 0 and count_skipack < 10:
                skipack_packet[seq] = True
                count_skipack += 1
            else:
                # If the sequence number of the packet has not been received yet
                if seq not in received_data:
                    print(f"Received packet with seq_num {seq}")
                    received_data[seq] = packet[HEADER_SIZE:]

                    # Write the data of the received packets to the file in order
                    while expected_seq_num in received_data:
                        print(f"Writing packet with seq_num {expected_seq_num} to file")
                        file.write(received_data[expected_seq_num])
                        del received_data[expected_seq_num]
                        expected_seq_num += 1

                # Create an acknowledgement packet for the received packet
                ack_packet = create_packet(0, seq, 4, 0, b"")
                print(f"Sending ACK for seq_num {seq}")

                # Send the acknowledgement packet to the sender
                sock.sendto(ack_packet, add_sender)


def run_server(server_ip, port, filename, reliability_mode, test_scenario, window_size):
    """
    Description:
    Function to run the server side of the file transfer application.

    Args:
        server_ip (str): IP address of the server
        port (int): Port number to bind the server
        filename (str): Name of the file to be received
        reliability_mode (str): Mode of the reliability protocol (stop_and_wait, gbn, sr)
        test_scenario (str): Scenario to test the reliability of the protocol
        window_size (int): Window size for the sliding window protocols
    """
    # Create UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Bind the socket to the specified IP and port
    server_socket.bind((server_ip, port))

    attempts = 0
    delay = 1

    print("Server: listening for client")
    # Connection establishment
    while attempts < MAX_ATTEMPTS:
        # Receive packet from client
        packet, client_address = server_socket.recvfrom(PACKET_SIZE)
        # Parse the packet header
        seq, ack, flags, win = parse_header(packet[:HEADER_SIZE])
        # Parse the flags from the packet
        syn, ack_flag, fin, rst = parse_flags(flags)

        if syn and not ack_flag:  # SYN flag is set
            # Send SYN-ACK
            print(f"syn received: {syn} and ack received: {ack_flag}")
            server_socket.sendto(create_packet(0, seq + 1, 12, window_size, b''), client_address)
        elif ack_flag:
            # ACK for SYN-ACK received
            print(f"ack for syn-ack received {ack_flag}")
            print("Server: 3-way handshake completed, connection with client established")
            break

        # Add a delay before the next attempt
        time.sleep(delay)
        attempts += 1

        if attempts > 1:
            print(f"Attempt {attempts}: Failed to establish connection. Retrying...")

    if attempts == MAX_ATTEMPTS:
        print("Failed to establish connection after maximum attempts. Exiting...")
        # Close the socket and exit the program if maximum attempts reached
        server_socket.close()
        sys.exit(1)

    # Depending on the reliability mode, call the respective function
    if reliability_mode == "stop_and_wait":
        print("start stop_and_wait")
        stop_and_wait_receiver(server_socket, filename, test_scenario)
        print("finished stop_and_wait")
    elif reliability_mode == "gbn":
        go_back_n_receiver(server_socket, filename, test_scenario, window_size)
    elif reliability_mode == "sr":
        selective_repeat_receiver(server_socket, filename, test_scenario)
    else:
        print("Invalid reliability mode.")

    # Connection teardown
    print("Server: Waiting for FIN from the client")

    while True:
        # Receive packet from client
        packet, client_address = server_socket.recvfrom(PACKET_SIZE)
        # Parse the packet header
        seq, ack, flags, win = parse_header(packet[:HEADER_SIZE])
        # Parse the flags from the packet
        syn, ack_flag, fin, rst = parse_flags(flags)

        if fin and not ack:  # FIN flag is set
            print("Server: Received FIN from the client")
            # Send ACK for FIN
            server_socket.sendto(create_packet(0, seq + 1, 4, window_size, b''), client_address)
            print("Server: Sent ACK for FIN")
            break

    # Close the socket after the connection
    server_socket.close()


def run_client(server_ip, port, filename, reliability_mode, test_scenario, window_size, calculate_timeout):
    """
    Description:
    The client function to establish connection, send data and teardown connection with the server.

    Args:
        server_ip (str): The IP address of the server.
        port (int): The port number of the server.
        filename (str): The name of the file to be sent.
        reliability_mode (str): The mode of reliable data transfer protocol (stop_and_wait, gbn or sr).
        test_scenario (str): The test scenario to be used.
        window_size (int): The size of the sender's window.
        calculate_timeout (bool): If True, sets the socket timeout based on the RTT.
    """
    # Create UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Initiate the 3-way handshake by sending SYN
    client_socket.sendto(create_packet(1, 0, 8, window_size, b''), (server_ip, port))
    # Setting timeout for socket
    client_socket.settimeout(TIMEOUT)

    # Wait for SYN-ACK from the server
    while True:
        try:
            packet, server_address = client_socket.recvfrom(PACKET_SIZE)
            seq, ack, flags, win = parse_header(packet[:HEADER_SIZE])
            syn, ack_flag, fin, rst = parse_flags(flags)

            if syn and ack_flag and ack == 2:  # SYN-ACK received
                # Send ACK for the received SYN-ACK to complete the 3-way handshake
                client_socket.sendto(create_packet(ack, 0, 4, window_size, b''), server_address)
                break

        except socket.timeout:
            # In case of timeout, resend SYN
            client_socket.sendto(create_packet(1, 0, 8, window_size, b''), (server_ip, port))

    print("Client: 3-way handshake completed, connection with server established")

    # Choose the reliable data transfer protocol based on the 'reliability_mode'
    if reliability_mode == "stop_and_wait":
        stop_and_wait_sender(client_socket, filename, server_ip, port, test_scenario, calculate_timeout)
    elif reliability_mode == "gbn":
        go_back_n_sender(client_socket, filename, server_ip, port, test_scenario, window_size, calculate_timeout)
    elif reliability_mode == "sr":
        selective_repeat_sender(client_socket, filename, server_ip, port, test_scenario, window_size, calculate_timeout)
    else:
        print("Invalid reliability mode.")

    # Connection teardown
    print("Client: Sending FIN")
    # Initiate the connection teardown by sending FIN
    client_socket.sendto(create_packet(seq, 0, 2, window_size, b''), (server_ip, port))

    attempts = 0
    delay = 1

    # Wait for ACK for FIN from the server
    while attempts < MAX_ATTEMPTS:
        packet, server_address = client_socket.recvfrom(PACKET_SIZE)
        seq, ack, flags, win = parse_header(packet[:HEADER_SIZE])
        syn, ack_flag, fin, rst = parse_flags(flags)

        if ack_flag:  # ACK for FIN received
            print("Client: Received ACK for FIN")
            break

        # If ACK for FIN is not received, wait for a while and resend FIN
        time.sleep(delay)
        client_socket.sendto(create_packet(seq, 0, 2, window_size, b''), (server_ip, port))  # Resend FIN
        attempts += 1
        print(f"Attempt {attempts}: Failed to teardown connection. Retrying...")

        if attempts == MAX_ATTEMPTS:
            print("Failed to teardown connection after maximum attempts. Exiting...")
            client_socket.close()
            sys.exit(1)  # Exit the program with an error code

    client_socket.close()  # Closing connection to server


def main():
    """
    Description:
        Main function to run the file transfer application.
        Parses command line arguments and runs the application in either server or client mode.
    """
    # Create a parser object
    parser = argparse.ArgumentParser(description="DATA2410 Reliable Transport Protocol (DRTP) File Transfer Application")

    # Add arguments to the parser
    parser.add_argument("-c", "--client", action="store_true", help="Run as client")
    parser.add_argument("-s", "--server", action="store_true", help="Run as server")
    parser.add_argument("-f", "--file_name", type=str, required=True, help="File to transfer")
    parser.add_argument("-r", "--reliability", type=str, choices=["stop_and_wait", "gbn", "sr"], help="Reliability function to use")
    parser.add_argument("-t", "--test", type=str, choices=["skipack", "loss"], help="Test scenario")
    parser.add_argument("-w", "--win_size", type=int, choices=[5, 10, 15], default=WINDOW_SIZE, help="Window size")
    parser.add_argument("-ct", "--calculate_timeout", type=bool, default=False, help='Calculates timeout based on previous rtt')
    parser.add_argument("-ip", "--server_ip", type=str, default=DEFAULT_IP, help='Server IP address (default: 127.0.0.1)')
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help="Port number (default: 8088)")

    # Parse the arguments
    args = parser.parse_args()

    # Validate the arguments
    if args.client and args.server:
        print("Cannot run as both client and server.")
        return

    if not args.client and not args.server:
        print("Must specify either client (-c) or server (-s).")
        return

    if args.client and not args.server_ip:
        print("Server address is required for client.")
        return

    # Run the application as a server or a client based on the arguments
    if args.server:
        run_server(args.server_ip, args.port, args.file_name, args.reliability, args.test, args.win_size)
    if args.client:
        run_client(args.server_ip, args.port, args.file_name, args.reliability, args.test, args.win_size, args.calculate_timeout)


if __name__ == "__main__":
    main()
