import logging
import scapy.layers.bluetooth as bt

from .helpers import setup_logging


class BluetoothHandler:
    """
    Representing a Bluetooth LE interface, and offering scanning, connecting, transmitting, etc
    Build upon the socket of the underlying socket_handler and Scapy HCI commands
    """

    # Programming handles, etc
    socket_handler = None
    logger = None
    name = None
    forwarding_bt_handler_dest = None
    seen_advertising_packets = []

    # Connection parameters
    connected_flag = None
    peer_bd_addr = None
    peer_addr_type = None
    connection_handle = None
    connection_role = None
    connection_interval = None
    min_connection_interval = None
    max_connection_interval = None
    connection_latency = None
    connection_timeout = None

    def __init__(self, name, socket_handler):
        # Overwrite __name__ with custom peripheral/central name and set up logging
        self.name = name
        setup_logging()
        self.logger = logging.getLogger(self.name)

        # Register socket_handler and define bluetooth connection as 'not connected to any device'
        self.socket_handler = socket_handler
        self.connected_flag = False

    def scan_enable(self):
        """ Set Scan Parameters and enable scanning """
        self.socket_handler.hci_send_command(bt.HCI_Cmd_LE_Set_Scan_Parameters())
        self.socket_handler.hci_send_command(bt.HCI_Cmd_LE_Set_Scan_Enable())
        print("{}: Scanning...".format(self.name))
        self.logger.info("Scanning...")

    def scan_disable(self):
        """ Disable Scanning """
        self.socket_handler.hci_send_command(bt.HCI_Cmd_LE_Set_Scan_Enable(enable=0x00))
        print("{}: Stopped Scanning.".format(self.name))
        self.logger.info("Stopped Scanning.")

    def connect(self, bd_addr, addr_type=None):
        """
        Send a Connection request to the specified BD_Addr; Do not populate the connection parameters yet, as connection
        is not yet confirmed. The connection parameters are populated once a Connection Complete Event occurs.
        """

        # If addr_type not specified, search for it in saved advertising packets
        if addr_type is None:
            # Find addr_type of
            for packet in self.seen_advertising_packets:
                if packet.addr == bd_addr:
                    addr_type = packet.atype

        # If addr_type not specified and not found in advertising packets, return
        if addr_type is None:
            print("{}: [-] Error. No address type (addr_type) for bd_addr to connect to found.".format(self.name))
            self.logger.error("{}: [-] Error. No address type (addr_type) for bd_addr to connect to found.")
            return

        self.socket_handler.hci_send(bt.HCI_Cmd_LE_Create_Connection(paddr=bd_addr, patype=addr_type))
        print("{}: Connection Request sent to {}.".format(self.name, bd_addr))
        self.logger.info("Connection Request sent to {}.".format(bd_addr))

    def disconnect(self):
        """ Disconnect the existing Bluetooth connection; Reset Connection Parameters """
        self.socket_handler.hci_send(bt.HCI_Cmd_Disconnect(handle=self.connection_handle))

        self.connected_flag = None
        self.peer_bd_addr = None
        self.peer_addr_type = None
        self.connection_handle = None
        self.connection_role = None
        self.connection_interval = None
        self.min_connection_interval = None
        self.max_connection_interval = None
        self.connection_latency = None
        self.connection_timeout = None

        print("{}: Disconnected and reset parameters.".format(self.name))
        self.logger.info("Disconnected and reset parameters.")

    def advertise_enable(self, spoofed_bd_addr=False):
        """ Advertise with scapy Standard Parameters and real device bd_addr if no spoofed_bd_addr specified """
        if spoofed_bd_addr:
            # adv_bd_addr = fake_bd_addr
            # self.socket_handler.hci_send(bt.HCI_Cmd_LE_Set_Advertising_Parameters())
            print("{}: Error. BD Address spoofing not yet implemented.".format(self.name))
            self.logger.error("{}: Error. BD Address spoofing not yet implemented.")
            raise NotImplemented

        else:
            adv_bd_addr = self.socket_handler.adapter_bd_addr
            self.socket_handler.hci_send(bt.HCI_Cmd_LE_Set_Advertising_Parameters())

        self.socket_handler.hci_send(bt.HCI_Cmd_LE_Set_Advertise_Enable(enable=0x01))
        print("{}: Enabled Advertising with BD_Addr: {}.".format(self.name, adv_bd_addr))
        self.logger.info("Enabled Advertising with BD_Addr: {}.".format(adv_bd_addr))

    def advertise_disable(self):
        """ Disable Advertising """
        self.socket_handler.hci_send(bt.HCI_Cmd_LE_Set_Advertise_Enable(enable=0x00))
        print("{}: Stopped Advertising.".format(self.name))
        self.logger.info("Stopped Advertising.")

    def imitate_advertise_enable(self, adv_packets_to_imitate, spoofed_bd_addr):
        """ advertised with imitated packet for 10s """
        # Spoof BD_Addr
        self.socket_handler.spoof_bd_addr(spoofed_bd_addr)

        # Set Advertising Parameters (Here only: set advertised addr_type to random)
        self.socket_handler.hci_send(bt.HCI_Cmd_LE_Set_Advertising_Parameters(oatype=1))

        # TODO Not yet properly concatenated multiple EIR_Hdr / multiple Advertising
        #      data. Therefore for now only copy The EIR_Hdr with the CompleteLocalName, as most important Advert. Data
        adv_data = None
        for packet in adv_packets_to_imitate:
            if bt.EIR_CompleteLocalName in packet:
                adv_data = packet[bt.EIR_Hdr]

        # Set Advertising Data
        if adv_data is not None:
            self.logger.debug("Imitated Advertising Data: {}".format(adv_data.show2(dump=True)))
            self.socket_handler.hci_send(bt.HCI_Cmd_LE_Set_Advertising_Data(data=adv_data))
        self.socket_handler.hci_send(bt.HCI_Cmd_LE_Set_Advertising_Data(data=adv_data))

        self.socket_handler.hci_send(bt.HCI_Cmd_LE_Set_Advertise_Enable(enable=0x01))

        imitated_bd_addr = adv_packets_to_imitate[0].addr
        print("{}: [+] Advertising Imitation of BD_Addr {} with spoofed BD_Addr {}."
              .format(self.name, imitated_bd_addr, spoofed_bd_addr))
        self.logger.info("[+] Advertising Imitation of BD_Addr {} with spoofed BD_Addr {}."
                         .format(imitated_bd_addr, spoofed_bd_addr))

    def register_att_forwarding_destination(self, bluetooth_handler):
        """ Register a Bluetooth Handler as the destination for ATT Data forwarding """
        self.forwarding_bt_handler_dest = bluetooth_handler

    def receive_att_data(self, received_att_packet):
        """ Send received forwarded ATT Data through own connection, given that a connection already exists """
        if self.connected_flag:
            # WARNING: The received packet is send as it is, also copying the connection header etc.
            #          This could potentially lead to errors as also the connection handle and connection parameters
            #          are copied, which could disagree with that different BT connection
            self.socket_handler.send_raw(received_att_packet)
            print("{}: Received ATT Data and sent it.".format(self.name))
            self.logger.info("Received ATT Data and sent it.")
        else:
            print("{}: [-] Received ATT Data, though discarded it as no connection established.".format(self.name))
            self.logger.info("[-] Received ATT Data, though discarded it as no connection established.")

    def handle_incoming_data(self):
        """ Receive incoming data, identify it and then either print it or call appropriate method in response """

        self.logger.debug("'handle_incoming_data' called. Receiving data from socket...")
        incoming_packet = self.socket_handler.receive_packet()
        if not incoming_packet:
            return

        self.logger.debug("[+] Received incoming_packet:\n###[ Structure ]###\n  {}\n{}"
                          .format(incoming_packet.summary(), incoming_packet.show2(dump=True)))

        # Identify incoming packet
        packet_type = self.identify_packet(incoming_packet)

        # Handle incoming packet according to identified type
        if packet_type == "ATT Data":
            # forward complete packet to registered Bluetooth_Handler, which sends it via his connection

            # For Better Verbosity print ATT Requests and Responses
            if bt.ATT_Read_By_Type_Request in incoming_packet:
                print("{}: Received Request:\n{}"
                      .format(self.name, incoming_packet[bt.ATT_Read_By_Type_Request].show2(dump=True)))
            elif bt.ATT_Read_By_Type_Response in incoming_packet:
                print("{}: Received Response:\n{}"
                      .format(self.name, incoming_packet[bt.ATT_Read_By_Type_Response].show2(dump=True)))
            else:
                print("{}: Received:\n{}".format(self.name, incoming_packet[bt.ATT_Hdr].show2(dump=True)))

            self.forwarding_bt_handler_dest.receive_att_data(incoming_packet)
            print("{}: Received and forwarded ATT Data.".format(self.name))
            self.logger.info("Received and forwarded ATT Data.")

        elif packet_type == "Connection Parameter Update Request":
            # Updates connection parameters according to request and responds with successful completion; p1771
            request_id = incoming_packet.id

            # update parameters according to request
            self.min_connection_interval = incoming_packet.min_interval
            self.max_connection_interval = incoming_packet.max_interval
            self.connection_latency = incoming_packet.slave_latency
            self.connection_timeout = incoming_packet.timeout_mult

            # update connection
            self.socket_handler.hci_send(bt.HCI_Cmd_LE_Connection_Update(
                handle=self.connection_handle, min_interval=self.min_connection_interval,
                max_interval=self.max_connection_interval, latency=self.connection_latency,
                timeout=self.connection_timeout))

            # send response about successfully updated connection
            self.socket_handler.l2cap_send(bt.L2CAP_Connection_Parameter_Update_Response(move_result=0x0000),
                                           self.connection_handle, request_id)

            print("{}: Received Connection Parameter Update Request; Updated Connection accordingly.".format(self.name))
            self.logger.info("Received Connection Parameter Update Request; Updated Connection accordingly.")

        elif packet_type == "Disconnection Complete Event":
            # Set connected flag and connected_bd_addr accordingly; print disconnection event; p1110
            self.connected_flag = False
            self.peer_bd_addr = None
            disconnection_msg = "[+] Disconnected." if incoming_packet.status == 0x00 else "[-] Disconnection failed."
            print("{}: {}".format(self.name, disconnection_msg))
            self.logger.info(disconnection_msg)

        elif packet_type == "Command Status Event":
            # Print current status of Command; p1123
            status_msg = "Command pending." if incoming_packet.status == 0x00 else "[-] Command failed."
            print("{}: {}".format(self.name, status_msg))
            self.logger.info(status_msg)

        elif packet_type == "Number of Complete Packets Event":
            # Print number of completed packets; p1128
            print("{}: Number of completed packets: {}".format(self.name, incoming_packet.number))
            self.logger.info("Number of completed packets: {}".format(incoming_packet.number))

        elif packet_type == "LE Connection Complete Event":
            # Populate Connection Parameters of stack; Print Status and important Parameters; p1190
            self.connected_flag = True
            self.peer_bd_addr = incoming_packet.paddr
            self.peer_addr_type = incoming_packet.patype
            self.connection_handle = incoming_packet.handle
            self.connection_role = incoming_packet.role
            self.connection_interval = incoming_packet.interval
            self.connection_latency = incoming_packet.latency
            self.connection_timeout = incoming_packet.supervision

            connection_msg = "[+] Connection with {} succesful. Handle: {}" \
                .format(self.peer_bd_addr, self.connection_handle) if incoming_packet.status == 0x00 else \
                "[-] Connection failed."

            print("{}: {}".format(self.name, connection_msg))
            self.logger.info(connection_msg)

        elif packet_type == "LE Advertising Report Event":
            # Append advertising packets to list of seen adv packets; Then print scanned infos; p1193

            # Check if incoming packet already seen
            seen_flag = False
            for packet in self.seen_advertising_packets:
                if packet.addr == incoming_packet.addr and packet.length == incoming_packet.length:
                    seen_flag = True

            # If not seen, append it to the list of seen advertising packets
            if not seen_flag:
                self.seen_advertising_packets.append(incoming_packet)

            possible_event_types = {0x00: "ADV_IND", 0x01: "ADV_DIRECT_IND", 0x02: "ADV_SCAN_IND",
                                    0x03: "ADV_NONCONN_IND", 0x04: "SCAN_RSP"}
            event_type = possible_event_types[incoming_packet.type]

            possible_addr_types = {0x00: "public", 0x01: "random", 0x02: "public identity",
                                   0x03: "random (static) identity"}
            addr_type = possible_addr_types[incoming_packet.atype]

            print("{}: Advertising: {} ({}) ({})".format(self.name, incoming_packet.addr, addr_type, event_type))
            self.logger.info("Advertising: {} ({}) ({})".format(incoming_packet.addr, addr_type, event_type))

        elif packet_type == "LE Connection Update Complete Event":
            # Check if confirmed Connection Update Parameters coincide with stack parameters; Print Status; p1195
            coincide_flag = True
            if incoming_packet.handle != self.connection_handle \
                    or incoming_packet.latency != self.connection_latency \
                    or incoming_packet != self.connection_interval \
                    or incoming_packet.timeout != self.connection_timeout:
                coincide_flag = False

            update_msg_1 = "[+] Connection Update Complete." if incoming_packet.status == 0x00 else \
                "[-] Connection Update Failed."

            update_msg_2 = "New Connection Parameters coincide." if coincide_flag else \
                "[-] Though new Connection Parameters differ."

            print("{}: {} {}".format(self.name, update_msg_1, update_msg_2))
            self.logger.info("{} {}".format(update_msg_1, update_msg_2))

        elif packet_type == "Unidentified":
            # TODO Implement Proper Handling of Command Complete Events
            # Though very small importance
            # Only Print warning of non-Command Complete Events, as those are actually important
            if bt.HCI_Event_Command_Complete not in incoming_packet:
                print("{}: WARNING, received unidentified package whose handling not yet implemented: {}".format(
                    self.name, incoming_packet.summary()))
                self.logger.warning(
                    "WARNING, received unidentified package whose handling not yet implemented: {}".format(
                        incoming_packet.summary()))

        else:
            print("{}: WARNING, identified an incoming packet as '{}', however handling not yet implemented."
                  .format(self.name, type))
            self.logger.warning("WARNING, identified an incoming packet as '{}', however handling not yet implemented."
                                .format(self.name, type))

    @staticmethod
    def identify_packet(incoming_packet):
        """ Identify packet type  according to Specs starting at p2400. Return type as string """

        # Check if packet type is 'HCI Command Packet'
        if incoming_packet.type == 0x01:
            pass

        # Check if packet type is 'HCI ACL Data Packet'
        elif incoming_packet.type == 0x02:

            # Check if ACL Data is ATT Data
            if bt.ATT_Hdr in incoming_packet:
                return "ATT Data"

            # Check if ACL Data is L2CAP Command, p1746
            elif bt.L2CAP_CmdHdr in incoming_packet:

                # Check if Command Code is 'Connection Parameter Update Request', p1771
                if incoming_packet.code == 0x12:
                    return "Connection Parameter Update Request"

        # Check if packet type is 'HCI Synchronous Data Packet'
        elif incoming_packet.type == 0x03:
            pass

        # Check if packet type is 'HCI Event Packet', p1104
        elif incoming_packet.type == 0x04:

            # Check if event code is 'Disconnection Complete Event', p1110
            if incoming_packet.code == 0x05:
                return "Disconnection Complete Event"

            # Check if event code is 'Command Status Event', p1123
            elif incoming_packet.code == 0x0f:
                return "Command Status Event"

            # Check if event code is 'Number of Completed Packets Event', p1128
            elif incoming_packet.code == 0x13:
                return "Number of Complete Packets Event"

            # Check if event code is 'LE Meta Event', p1190
            elif incoming_packet.code == 0x3e:

                # Check if subevent code is 'LE Connection Complete Event', p1190
                if incoming_packet.event == 0x01:
                    return "LE Connection Complete Event"

                # Check if subevent code is 'LE Advertising Report Event', p1193
                elif incoming_packet.event == 0x02:
                    return "LE Advertising Report Event"

                # Check if subevent code is 'LE Connection Update Complete Event', p1195
                elif incoming_packet.event == 0x03:
                    return "LE Connection Update Complete Event"

        # Catch all, for packages whose identification not yet implemented
        return "Unidentified"
