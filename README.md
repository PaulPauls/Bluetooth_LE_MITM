Man in the Middle Programm between a BTLE Peripheral (e.g. IoT Device) and BTLE Central (e.g. Smartphone).
It tries to connect to an advertising peripheral, shutting down its advertising in best case, then imitates the
advertising packages from the peripheral itself with an arbitrarily spoofed BD_Addr (can be the same as peripheral).
A victim will then connect to the spoofed peripheral, thinking it would be the real one due to its identical advertising
data. Any ATT data exchanged between the real peripheral and the real central will then be tunneled through the MITM
station and displayed while upholding both seperate connections independently.



#### Code Structure ####

Code is completely documented in-line with docstrings for all if not the simplest methods, though it's mostly self
explanatory code anyways. Coded in accordance to PEP 8 Styleguide.

As the MITM station requires two Bluetooth stack (for fake central and fake peripheral) does the main initialize two
seperate pairs of underlying sockets and bluetooth stacks. The Socket Handler takes care of everything low level from
Host Controller interface to Socket, while the Bluetooth Handler implements the Bluetooth Stack Logic and provides
the Function interface. The MITM_Handler unites both Bluetooth Stacks and directs the attack commands to the appropriate
Bluetooth Stack, while also implementing the MITM_Logic. The Interactive_Session does not add functionality but does
instead allow the interactive operation of the MITM_Handler (/BTLE_MITM), while constantly requesting the handling
of new incoming data.

Object Interfaces are kept to a minimum and only directed upwards (Socket_Handler <- Bluetooth_Handler <- MITM_Handler
<- Interactive_Session) for optimal encapsulation, though this is broken once in regards to the Bluetooth_Handlers as
they are made known to each other to enable direct forwarding of ATT Data to the respectively other Bluetooth Stack.



#### Application Example ####

Equipment used for testing during development:
- 3x USB Dongle
- 1x Adafruit LE Friend

Complete Application Procedure:
(X represents in all steps the number of the Host Controller Interface to use)

- Optional: During all testing, inspect commands issued on the Interface using 'btmon -i X'

- sample configure the BTLE peripheral 'Adafruit LE Friend' according to:
    https://learn.adafruit.com/introducing-adafruit-ble-bluetooth-low-energy-friend/command-examples
    Among other things will this provide the Heart Rate Measurement characteristic with UUID=0x2A37

- Using hci2, scan with hcitool to confirm the presence of the Adafruit LE Friend: $ hcitool -i hci2 lescan

- Start BTLE_MITM and scan for victims to be imitated, using in the interactive console: $ self.scan_enable()

- When victim found, stop scanning: $ self.scan_disable()

- Connect to the victim and imitate its BD_Addr (or choose any other BD_ADDR) with
    $ self.connect_and_imitate('<BD_ADDR_TO_BE_ATTACKED>', '<SPOOFED_BD_ADDR>'

    E.g.: After having scanned the BD_ADDR cb:10:26:7d:4f:f7, will I connect to it and create a very similar
    advertisement with the BD_ADDR cb:10:26:7d:4f:f6:
    $ self.connect_and_imitate('cb:10:26:7d:4f:f7', 'cb:10:26:7d:4f:f6'

- Now Scan with hci2 (our victim central which will connect to the imitated BD_Addr) for advertising BD_Addr to
    connect to with: $ hcitool -i hci2 lescan

    Sample output:
    LE Scan ...
    CB:10:26:7D:4F:F6 Adafruit Bluefruit LE
    CB:10:26:7D:4F:F6 (unknown)
    ...

- Connect via gatttool hci2 to the faked peripheral via:
    $ gatttool -b cb:10:26:7d:4f:f6 -t random --adapter=hci2 --interactive
    $ connect

- Receive a List of all Handles from the hci2 central: $ char-desc
- Read/Write single handles, e.g. Char 0x2a37 via: $ char-read-uuid 0x2A37
- Change Value of Handle on Adafruit LE Friend with command: $ AT+GATTCHAR=1,00-5C
- Read/Write again changed single handle, e.g. Char 0x2a37 via: $ char-read-uuid 0x2A37

- All of the GATT Data Exchange above should be protocolled and displayed by BTLE_MITM on stdout as well as in the
    debug.log / info.log even more extensively

- Properly disconnect victim central via command in gatttool: $ disconnect

- Properly close BTLE_MITM by issuing:
    $ self.advertise_disable()
    $ self.disconnect()
    $ Ctrl-D    [to exit Interactive Console and then automatically close sockets properly]



#### Bugs and Improvements ####

Bugs:
- InteractiveConsole occasionally freezes (usually after the first command). This seems to be a problem with Python
    as it is not deterministic, doesn't throw an error and also occurs in other projects
- When automatically updating connection parameters (necessary to uphold connection), BTLE_MITM shows a warning about ]
    differing connection parameters. This is not crucial and does influence the connection stability so far.

Improvements:
- Advertising data sometimes scattered over 'conn_und' and 'scan_rsp' packets. Currently only copying advertising
    data which entails EIR_CompleteLocalName. Therefore properly concatenate multiple EIR_Hdr Data.
    (see TODO in bluetooth_handler.py)
- Properly handle the 'Command Complete Event'. Currently ignored because of limited use and little time.
    (see TODO in bluetooth_handler.py)
- Make HCI Adapters (Currently set to adapter 0 (hci0) and adapter 1 (hci1) hardcoded in main.py) an argument
    via argparse. (see main.py)
