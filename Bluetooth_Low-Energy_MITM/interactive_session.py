import code
import logging
from threading import Thread

from .helpers import setup_logging

# Set up logging
setup_logging()
logger = logging.getLogger(__name__)


class InteractiveSession:
    """
    Starting an InteractiveConsole and constantly checking
    """

    mitm_handler = None

    def __init__(self, mitm_handler):
        self.mitm_handler = mitm_handler

        # Create InteractiveConsole shell that inherits environment and starts in a new Thread
        # To correctly end the InteractiveConsole use CTRL+D
        logger.info("[!] Starting InteractiveConsole shell...")
        variables = {**globals(), **locals()}
        shell = code.InteractiveConsole(variables)
        shell_thread = Thread(target=shell.interact)
        shell_thread.start()

        # Start loop for mitm_handler to continuously check incoming data while the shell_thread is alive.
        while shell_thread.is_alive():
            self.mitm_handler.handle_incoming_data()

    def scan_enable(self):
        self.mitm_handler.scan_enable()

    def scan_disable(self):
        self.mitm_handler.scan_disable()

    def advertise_enable(self):
        self.mitm_handler.advertise_enable()

    def advertise_disable(self):
        self.mitm_handler.advertise_disable()

    def connect(self, bd_addr):
        self.mitm_handler.connect(bd_addr)

    def disconnect(self):
        self.mitm_handler.disconnect()

    def connect_and_imitate(self, imitated_bd_addr, spoofed_bd_addr):
        self.mitm_handler.connect(imitated_bd_addr)
        self.mitm_handler.imitate_advertise_enable(imitated_bd_addr, spoofed_bd_addr)

    def imitate_advertise_enable(self, imitated_bd_addr, spoofed_bd_addr):
        self.mitm_handler.imitate_advertise_enable(imitated_bd_addr, spoofed_bd_addr)
