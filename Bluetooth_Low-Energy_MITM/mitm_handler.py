import logging

from .helpers import setup_logging

# Set up logging
setup_logging()
logger = logging.getLogger(__name__)


class MITMHandler:
    """
    Abstracting the use of two Bluetooth Stacks by passing commands to the appropriate Handler in accordance to the
    idea behind BTLE MITM, especielly who has to communicate with whom after which action and vice versa.
    """

    bluetooth_handler_peripheral = None
    bluetooth_handler_central = None

    def __init__(self, bluetooth_handler_peripheral, bluetooth_handler_central):
        # Register both peripheral and central bluetooth handlers
        self.bluetooth_handler_peripheral = bluetooth_handler_peripheral
        self.bluetooth_handler_central = bluetooth_handler_central

        # Register both bluetooth handlers as the forwarding destinations of each other
        self.bluetooth_handler_central.register_att_forwarding_destination(bluetooth_handler_peripheral)
        self.bluetooth_handler_peripheral.register_att_forwarding_destination(bluetooth_handler_central)

    def scan_enable(self):
        """ Let Central scan for external peripherals, as the central BT Handler will also connect to it """
        logger.debug("Enable scanning by central Bluetooth Handler...")
        self.bluetooth_handler_central.scan_enable()

    def scan_disable(self):
        """ Disable Scanning by the central Bluetooth Handler """
        logger.debug("Disable scanning by central Bluetooth Handler...")
        self.bluetooth_handler_central.scan_disable()

    def advertise_enable(self):
        """ Let Periphercal advertise """
        logger.debug("Enable advertising by peripheral Bluetooth Handler...")
        self.bluetooth_handler_peripheral.advertise_enable()

    def advertise_disable(self):
        """ Disable advertising by the peripheral Bluetooth Handler """
        logger.debug("Disable advertising by peripheral Bluetooth Handler...")
        self.bluetooth_handler_peripheral.advertise_disable()

    def connect(self, bd_addr, addr_type=None):
        """ Let Central connect to specified BD Addr """
        logger.debug("Initiate connection by central Bluetooth Handler...")
        self.bluetooth_handler_central.connect(bd_addr, addr_type)

    def disconnect(self):
        """ Disconnect Central """
        logger.debug("Initiate disconnect by central Bluetooth Handler...")
        self.bluetooth_handler_central.disconnect()

    def imitate_advertise_enable(self, imitated_bd_addr, spoofed_bd_addr):
        """ Let Peripheral advertise with spoofed_bd_addr and the advertising packets the central found """
        # Based on the bd_addr to be imitated, get all its corresponding advertising packets as a list. Use therefore
        # the list of all seen advertising packets that central already scanned
        adv_packets_to_imitate = []
        for packet in self.bluetooth_handler_central.seen_advertising_packets:
            if packet.addr == imitated_bd_addr:
                adv_packets_to_imitate.append(packet)

        if len(adv_packets_to_imitate) == 0:
            print("[-] Error. No Advertising packages found of the bd_addr that is supposed to be imitated.")
            logger.error("[-] Error. No Advertising packages found of the bd_addr that is supposed to be imitated.")
            return

        logger.debug("Enable IMITATED advertising by peripheral Bluetooth Handler...")
        self.bluetooth_handler_peripheral.imitate_advertise_enable(adv_packets_to_imitate, spoofed_bd_addr)

    def handle_incoming_data(self):
        self.bluetooth_handler_peripheral.handle_incoming_data()
        self.bluetooth_handler_central.handle_incoming_data()

    def close_sockets(self):
        self.bluetooth_handler_peripheral.socket_handler.socket.close()
        self.bluetooth_handler_central.socket_handler.socket.close()
