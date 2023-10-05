# DATA2410 Reliable Transport Protocol (DRTP) File Transfer Application

This application is a Python script for file transfer using a Reliable Transport Protocol (DRTP). It implements a reliable file transfer over UDP, and the problem we are solving is to send data reliably. This means that data sent is delivered in-order and without missing data or duplicates. The ability to transfer large files quickly and efficiently has become essential, and this is what we are trying to do with this application 

It supports three different reliability methods: Stop and Wait (S&W), Go-Back-N (GBN), and Selective Repeat (SR). The application can be run in either client or server mode. 

### Table of Contents
**[Usage Instructions](#usage-instructions)**<br>
**[How to run the application](#example)**<br>
**[File Structure](#file-structure)**<br>
**[Features](#features)**<br>
**[Functions](#the-script-contains-the-following-main-functions)**<br>

## Usage Instructions
The application currently only supports a single client-server pair, and does not support multiple concurrent clients. Also, the application assumes reliable delivery of ACKs in the Stop-and-Wait and Go-Back-N modes. Only in the Selective Repeat mode does it handle the scenario where ACKs are lost.

Command Line Arguments that can be used when running the script:

    -c or --client: Invoke the application as a client.

    -s or --server: Invoke the application as a server.

    -f or --file: The name of the file to transfer.

    -r or --reliability: The reliability method to use, which can be one of the following: stop_and_wait, gbn, or sr.

    -t or --test: The test scenario to use, which can be one of the following: skipack or loss.

    -ip or --ip: The server IP address. This is optional, and if not provided, a default IP will be used.

    -p or --port: The server port number. This is optional, and if not provided, a default port will be used.

    -w or --window: The window size to be used. This is optional, and if not provided, a default size of 5 will be used.
    
    -ct or --calculate_timeout: Calculates timeout based on previous rtt time.

### Running the Script
To run the script, use the following commands in the terminal, replacing the placeholders with your own values:

Server mode:

    python3 application.py -s -r `<reliability method>` -ip `<server IP>` -p `<server port>` -f `<file name>`
    
Client mode:
    
    python3 application.py -c -r `<reliability method>` -ip `<server IP>` -p `<server port>` -f `<file name>`
    
Additional options for server and client:

    -t `<test case>` (choices: "skipack" and "loss"), must be invoked from both server and client side

    -w `<window size>` (choices: 5, 10 and 15), only needs to be invoked from client side.
    
## Example
To run as a server:

    python3 application.py -s -f photo_new.jpeg -r gbn -ip 127.0.0.1 -p 12345

To run as client:

    python3 application.py -c -f photo.jpeg -r gbn -ip 127.0.0.1 -p 12345
    

## File Structure

```
Portfolio2/
├── README.md
├── src
│   └── application.py
├── simple-topo.py
├── s362063_s362112_s315297_s362086_portfolio2.pdf
├── Measurements
│   ├── Test_case_tc-netem
│   │   ├── netem-reordering
│   │   │   ├── reorder_netem_stop_and_wait_server.txt
│   │   │   ├── reorder_netem_stop_and_wait_client.txt
│   │   │   ├── reorder_netem_sr_server.txt
│   │   │   ├── reorder_netem_sr_client.txt
│   │   │   ├── reorder_netem_gbn_server.txt
│   │   │   └── reorder_netem_gbn_client.txt
│   │   ├── netem-loss
│   │   │   ├── loss_netem_stop_and_wait_server.txt
│   │   │   ├── loss_netem_stop_and_wait_client.txt
│   │   │   ├── loss_netem_sr_server.txt
│   │   │   ├── loss_netem_sr_client.txt
│   │   │   ├── loss_netem_gbn_server.txt
│   │   │   └── loss_netem_gbn_client.txt
│   │   └── netem-duplicate
│   │       ├── dup_netem_stop_and_wait_server.txt
│   │       ├── dup_netem_stop_and_wait_client.txt
│   │       ├── dup_netem_sr_server.txt
│   │       ├── dup_netem_sr_client.txt
│   │       ├── dup_netem_gbn_server.txt
│   │       └── dup_netem_gbn_client.txt
│   ├── Test_case_3
│   │   ├── sr_skiseq_server.txt
│   │   ├── sr_skiseq_client.txt
│   │   ├── gbn_skiseq_server.txt
│   │   └── gbn_skiseq_client.txt
│   ├── Test_case_2
│   │   ├── stop_and_wait_skipack_server.txt
│   │   ├── stop_and_wait_skipack_client.txt
│   │   ├── sr_skipack_server.txt
│   │   ├── sr_skipack_client.txt
│   │   ├── gbn_skipack_server.txt
│   │   └── gbn_skipack_client.txt
│   └── Test_case_1
│       ├── stop_and_wait-50rtt.txt
│       ├── stop_and_wait-25rtt.txt
│       ├── stop_and_wait-100rtt.txt
│       ├── GBN-SR-5w-50rtt.txt
│       ├── GBN-SR-5w-25rtt.txt
│       ├── GBN-SR-5w-100rtt.txt
│       ├── GBN-SR-15w-50rtt.txt
│       ├── GBN-SR-15w-25rtt.txt
│       ├── GBN-SR-15w-100rtt.txt
│       ├── GBN-SR-10w-50rtt.txt
│       ├── GBN-SR-10w-25rtt.txt
│       ├── GBN-SR-10w-100rtt.txt
│       ├── GBN-5w-50rtt.txt
│       ├── GBN-5w-25rtt.txt
│       ├── GBN-5w-100rtt.txt
│       ├── GBN-15w-50rtt.txt
│       ├── GBN-15w-25rtt.txt
│       ├── GBN-15w-100rtt.txt
│       ├── GBN-10w-50rtt.txt
│       ├── GBN-10w-25rtt.txt
│       └── GBN-10w-100rtt.txt
```


## Features
Reliable File Transfer: 
The application ensures reliable file transfer using three different methods - Stop and Wait, Go-Back-N, and Selective Repeat.

The server IP, port, reliability method, window size, and other parameters can be customized.

Testing Functionality: 
It includes testing scenarios such as skipping acknowledgement, packet loss, duplicate packets and out of order packets.
Throughput Calculation: The application also calculates and displays the throughput of the file transfer.
Usage
Roundtrip time (RTT): It can calculates the per-packet roundtrip time, rather then using fixed timeout to set timeout.


## The script contains the following main functions
create_packet(seq, ack, flags, win, data): This function takes in various parameters representing the sequence number, acknowledgement number, flags, window size, and data. It creates a packet by packing these fields into a binary representation and concatenates the header and data.

parse_header(header): This function takes a binary header as input and unpacks it into individual fields, returning a tuple containing the parsed fields of the header.

parse_flags(flags): This function takes the flags field of a packet and extracts the individual flag values (syn, ack, fin, rst) using bitwise AND operations. It returns a tuple containing the parsed flag values.

stop_and_wait_sender(sock, file_name, address, port, test_scenario=None, ct=False): This function implements the stop-and-wait protocol for sending packets over a socket connection. It reads the specified file, divides it into packets, and sends them one by one. It waits for the acknowledgement of each packet before sending the next one.

stop_and_wait_receiver(sock, file_name, test_scenario=None): This function implements the stop-and-wait protocol for receiving packets over a socket connection. It receives packets, checks their sequence numbers, sends acknowledgements for the correct packets, and writes the received data to a file.

go_back_n_sender(sock, file_name, address, port, test_scenario=None, window_size=WINDOW_SIZE, ct=False): This function implements the Go-Back-N protocol for sending packets over a socket connection. It reads the specified file, divides it into packets, and sends them in a sliding window fashion. It keeps track of the acknowledgements received and resends any unacknowledged packets after a timeout.

go_back_n_receiver(sock, file_name, test_scenario=None, window_size=WINDOW_SIZE): This function implements the Go-Back-N protocol for receiving packets over a socket connection. It receives packets, checks their sequence numbers, sends acknowledgements for the correct packets, and writes the received data to a file.

selective_repeat_sender(sock, file_name, address, port, test_scenario=None, win_size=WINDOW_SIZE, rtt=False): This function implements the Selective Repeat protocol for sending packets over a socket connection. It reads the specified file, divides it into packets, and sends them with sequence numbers. It keeps track of the acknowledgements received and resends any unacknowledged packets after a timeout.

selective_repeat_receiver(sock, file_name, test_scenario=None): This function implements the Selective Repeat protocol for receiving packets over a socket connection. It receives packets, checks their sequence numbers, sends acknowledgements for the correct packets, and writes the received data to a file.

run_server(server_ip, port, filename, reliability_mode, test_scenario, window_size): This function runs the server-side of the file transfer application. It establishes a connection with the client, receives packets, and invokes the appropriate reliability protocol function to handle the received packets.

run_client(server_ip, port, filename, reliability_mode, test_scenario, window_size, calculate_timeout): This function runs the client-side of the file transfer application. It establishes a connection with the server, reads the specified file, divides it into packets, and sends them using the specified reliability protocol.

main(): This function parses the command-line arguments, checks the selected mode (client or server), and invokes the corresponding function (run_server or run_client) based on the provided arguments.


