## Man-in-the-Middle Relay program between a Bluetooth Low-Energy (BTLE) Peripheral and Central ##

Man-in-the-Middle Relay program between a Bluetooth Low-Energy (**BTLE**) Peripheral (eg IoT Device) and Central (eg Smartphone) built atop the great package manipulation tool [Scapy](https://github.com/secdev/scapy).

The program scans for advertising peripherals, offers the option to connect to one, then connects to this advertising peripheral, shutting down the advertising of this peripheral, then imitates the exact same advertising packages from the peripheral itself with an arbitrarily spoofed `BD_Addr` (can be the same as peripheral, as it allows to change the own Hardware `BD_Addr` as well).
A victim will then connect to the spoofed peripheral, thinking it would be the real desired peripheral due to its identical advertising data. Any Attribute Protocol (**ATT**) data exchanged between the real peripheral and the real central will then be tunneled through the MITM relay station and displayed while upholding both seperate connections independently.



#### Code Structure ####

Code is completely documented in-line with docstrings for all except the simplest methods, though it's mostly self explanatory code anyways. The code follows the simple multi-layered architecture, employs Object-Orientation whereever possible and is in accordance to PEP 8 Styleguide.

As the MITM station requires two Bluetooth stacks (one each the for the fake central and fake peripheral) does the main-routine initialize two seperate pairs of underlying sockets and bluetooth stacks. The `socket_handler` takes care of everything low level from the *Host Controller Interface (HCI)* to the handling of the *socket*, while the `bluetooth_handler` implements the Bluetooth stack logic and provides the function interfaces. The `mitm_handler` unites both Bluetooth stacks and directs the attack commands to the appropriate stack, while also implementing the Man-in-the-Middle logic. The `Interactive_Session` does not add functionality but does instead allow the interactive operation of the `mitm_handler`, while constantly requesting the handling of new incoming data.

Object Interfaces are kept to a minimum and only directed upwards (`socket_handler` <- `bluetooth_handler` <- `mitm_handler`
<- `interactive_session`) to maximize cohesion and minimize coupling (though this is broken once in regards to the `bluetooth_handlers` as
they are made known to each other to enable direct forwarding of ATT Data to the respectively other Bluetooth stack.



#### Application Example ####

Equipment used in this application example:
* 3x USB Bluetooth Dongle
* 1x Adafruit LE Friend

*X represents in all steps the index of the Host Controller Interface to use*

0. Optional: During all testing, inspect commands issued on the Interface using `$ btmon -i X`

1. Sample configure the BTLE peripheral 'Adafruit LE Friend' according to [Adafruit LE Friend Tutorial](https://learn.adafruit.com/introducing-adafruit-ble-bluetooth-low-energy-friend/command-examples).
   Among other things will this provide the Heart Rate Measurement characteristic with UUID=0x2A37.

2. Using `hci2` (our victim central which will connect to the imitated `BD_Addr`), scan with hcitool to confirm the presence of the Adafruit LE Friend: `$ hcitool -i hci2 lescan`

3. Start `BTLE_MITM` and scan for victims to be imitated, using in the interactive console: `$ self.scan_enable()`

4. When victim has been found, stop scanning: `$ self.scan_disable()`

5. Connect to the victim and imitate its `BD_Addr` (or choose any other `BD_ADDR`) with
    $ self.connect_and_imitate('<BD_ADDR_TO_BE_ATTACKED>', '<SPOOFED_BD_ADDR>'

   E.g.: After having scanned the `BD_ADDR` cb:10:26:7d:4f:f7, will I connect to it and create a very similar advertisement with the `BD_ADDR` cb:10:26:7d:4f:f6:
    $ self.connect_and_imitate('cb:10:26:7d:4f:f7', 'cb:10:26:7d:4f:f6'

6. Now Scan with `hci2` (our victim central which will connect to the imitated BD_Addr) for advertising `BD_Addr` to connect to with: `$ hcitool -i hci2 lescan`
   Sample output:
    LE Scan ...
    CB:10:26:7D:4F:F6 Adafruit Bluefruit LE
    CB:10:26:7D:4F:F6 (unknown)
    ...

7. Via gatttool connect hci2 to the faked peripheral with:
    $ gatttool -b cb:10:26:7d:4f:f6 -t random --adapter=hci2 --interactive
    $ connect

8. Receive a list of all handles from the hci2 central: `$ char-desc`

9. Read/Write single handles, e.g. Char 0x2a37 via: `$ char-read-uuid 0x2A37`

10. Change Value of Handle on Adafruit LE Friend with command: `$ AT+GATTCHAR=1,00-5C`

11. Read/Write again changed single handle, e.g. Char 0x2a37 via: `$ char-read-uuid 0x2A37`

12. All of the GATT data exchange above should be protocolled and displayed by `BTLE_MITM` on stdout as well as in the debug.log and info.log even more extensively

13. Properly disconnect victim central via command in gatttool: `$ disconnect`

14. Properly close `BTLE_MITM` by issuing:
    $ self.advertise_disable()
    $ self.disconnect()
    $ Ctrl-D    [to exit Interactive Console and then automatically close sockets properly]



#### Bugs and Improvements ####

Bugs:
* InteractiveConsole occasionally freezes. This seems to be a problem with the python's own `interactive_console` librayr as it is not deterministic, doesn't throw an error and also occurs in other projects
* When automatically updating connection parameters (necessary to uphold connection), `BTLE_MITM` shows a warning about slightly differing connection parameters. This is not crucial and does influence the connection stability as far as tested.

Improvements:
* Advertising data sometimes scattered over `conn_und` and `scan_rsp` packets. Currently only copying advertising data which entails `EIR_CompleteLocalName`. Proper concatenation of multiple `EIR_Hdr` data streams to be done (see TODO in `bluetooth_handler.py`).
* Properly handle the `Command Complete Event`. Currently ignored because of limited use and little time (see TODO in `bluetooth_handler.py`).
* Make HCI adapters (Currently set to adapter 0 (hci0) and adapter 1 (hci1) hardcoded in main.py) an argument via argparse. (see `main.py`)

Feedback welcome.

