import logging
import datetime

from .helpers import setup_logging
from .socket_handler import SocketHandler
from .bluetooth_handler import BluetoothHandler
from .mitm_handler import MITMHandler
from .interactive_session import InteractiveSession

# Set up logging
setup_logging()
logger = logging.getLogger(__name__)


def main():
    print("Starting Bluetooth Low-Energy MITM. Timestamp: {}".format(datetime.datetime.now()))
    logger.info("\n\n\n\nStarting Bluetooth Low-Energy MITM. Timestamp: {}".format(datetime.datetime.now()))

    # Initialize two seperate (Peripheral and Central) Socket Handler and acquire the Bluetooth sockets
    socket_handler_peripheral = SocketHandler("__socket_handler_peripheral__", 0)
    socket_handler_central = SocketHandler("__socket_handler_central__", 1)

    # Initialize two seperate (Peripheral and Central) Bluetooth Handlers (representing the actual Bluetooth Interface)
    # and connect them with their according Socket Handler
    bluetooth_handler_peripheral = BluetoothHandler("__bluetooth_handler_peripheral__", socket_handler_peripheral)
    bluetooth_handler_central = BluetoothHandler("__bluetooth_handler_central__", socket_handler_central)

    # Unite both Bluetooth Handlers in a Man-in-the-Middle Handler, abstracting scanning, connecting, mimicking etc
    # to one interface and directing the commands to the appropriate Bluetooth Handler
    mitm_handler = MITMHandler(bluetooth_handler_peripheral, bluetooth_handler_central)

    # Start Interactive Session that allows for input commands such as scanning, connecting, etc and controls
    # controls both Bluetooth stacks via the Man-in-the-Middle Handler
    InteractiveSession(mitm_handler)

    # Close Sockets before exiting
    mitm_handler.close_sockets()


if __name__ == '__main__':
    main()
