import sys
import socket
import select
import logging
import scapy.layers.bluetooth as bt
from fcntl import ioctl

from .helpers import setup_logging


class SocketHandler:
    """
    Handles everything low-Level ranging from Socket to Host-Controller-Interface, though usually by providing a
    convenient interface to scapy
    """

    socket = None
    hci_adapter = None
    adapter_bd_addr = None
    spoofed_bd_addr = None
    logger = None
    name = None

    def __init__(self, name, hci_adapter):
        # Overwrite self.name with custom peripheral/central name and set up logging
        self.name = name
        setup_logging()
        self.logger = logging.getLogger(self.name)

        self.hci_adapter = hci_adapter

        # Get socket using specified hci_adapter
        self.socket = self.get_socket(hci_adapter)
        print("[+] {}: Socket acquired successfully".format(self.name))
        self.logger.info("[+] Socket acquired successfully")

        # Reset Settings of HCI Adapter
        self.hci_send_command(bt.HCI_Cmd_Reset())
        print("[+] {}: Settings of HCI Adapter resetted".format(self.name))
        self.logger.info("[+] Settings of HCI Adapter resetted")

        # Find out BD_Address of specified hci_adapter
        self.adapter_bd_addr = self.get_bd_addr()
        print("{}: BD_Addr of Adapter: {}".format(self.name, self.adapter_bd_addr))
        self.logger.info("BD_Addr of Adapter: {}".format(self.adapter_bd_addr))

    def get_socket(self, hci_adapter):
        self.logger.debug("Acquiring Socket on hci adapter {}".format(hci_adapter))

        try:
            # Preemptively take down specified HCI Adapter as this status is required by scapys 'BluetoothUserSocket'.
            # If HCI Adapter is already down, calling this function has no effect.
            self.hci_down(hci_adapter)
            return bt.BluetoothUserSocket(hci_adapter)

        except bt.BluetoothSocketError as e:
            print("[-] Creating socket on adapter {} failed for reason: {}\nProgram executed as root!?"
                  .format(hci_adapter, e))
            self.logger.error("[-] Creating socket on adapter {} failed for reason: {}\nProgram executed as root!?"
                              .format(hci_adapter, e))
            sys.exit(1)

    def get_bd_addr(self):
        tmp = self.hci_send_command(bt.HCI_Cmd_Read_BD_Addr())
        return tmp[bt.HCI_Cmd_Complete_Read_BD_Addr].addr

    def spoof_bd_addr(self, spoofed_bd_addr):
        self.spoofed_bd_addr = spoofed_bd_addr
        self.hci_send_command(bt.HCI_Cmd_LE_Set_Random_Address(address=spoofed_bd_addr))
        print("{}: [+] BD_Addr spoofed and set to {}".format(self.name, spoofed_bd_addr))
        self.logger.info("[+] BD_Addr spoofed and set to {}".format(spoofed_bd_addr))

    def hci_send_command(self, cmd):
        """ send HCI Command via acquired socket and block waiting for an answer """
        return self.socket.send_command(bt.HCI_Hdr() / bt.HCI_Command_Hdr() / cmd)

    def hci_send(self, cmd):
        """ send HCI Command via acquired socket BUT DON'T block waiting for an answer """
        packet = bt.HCI_Hdr() / bt.HCI_Command_Hdr() / cmd
        self.logger.debug("Packet to be send out with 'hci_send':\n###[ Structure ]###\n  {}\n{}"
                          .format(packet.summary(), packet.show2(dump=True)))
        return self.socket.send(packet)

    def l2cap_send(self, cmd, handle, request_id):
        """ send non-blocking L2CAP command with specified handle and id """
        return self.socket.send(bt.HCI_Hdr() / bt.HCI_ACL_Hdr(handle=handle) / bt.L2CAP_Hdr() /
                                bt.L2CAP_CmdHdr(id=request_id) / cmd)

    def send_raw(self, packet):
        """ send specified packet 'as it is' via socket """
        self.logger.debug("Packet to be send out with 'send_raw':\n###[ Structure ]###\n  {}\n{}"
                          .format(packet.summary(), packet.show2(dump=True)))
        return self.socket.send(packet)

    def receive_packet(self):
        """ Wait for packet on socket to be available (Timeout 3s) and return it, otherwise return False flag """
        packet_ready = select.select([self.socket], [], [], 3)

        if packet_ready[0]:
            return self.socket.recv()
        else:
            return False

    @staticmethod
    def hci_down(hci_adapter):
        """
        Takes specified HCI Adapter down; Copied over from PyBT; tested though unsure if correct as taken as black magic
        """
        # 31 => PF_BLUETOOTH
        # 0 => HCI_CHANNEL_USER
        # 0x400448ca => HCIDEVDOWN
        sock = socket.socket(31, socket.SOCK_RAW, 1)
        ioctl(sock.fileno(), 0x400448ca, hci_adapter)
        sock.close()
        return True
