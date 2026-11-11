Core 0 and core 1 configure semihosting STDIO

| Source | Log message |
| --- | --- |
| [STD:0348](pyocd/utility/stdio.py#L348) | `0000150 D STDIO 0: Mode: 'console' [stdio]` |
| [STD:0348](pyocd/utility/stdio.py#L348) | `0000180 D STDIO 1: Mode: 'server' [stdio]` |
| [TCP:0086](pyocd/utility/server.py#L86) | `0000185 I STDIO 1: Server started on port 4444 [server]` |
| [GDB:0424](pyocd/gdbserver/gdbserver.py#L424) | `        0000190 E Server 1: Failed to initialize RTT/SystemView support: example error; RTT setup disabled [gdbserver]` |
| [RTM:0248](pyocd/utility/rtt_manager.py#L248) | `        0000160 D RTT 0: Failed to get _SEGGER_RTT symbol address from ELF: example error [rtt_manager]` |
| [RTM:0299](pyocd/utility/rtt_manager.py#L299) | `        0000210 W RTT 0: No _SEGGER_RTT symbol available; cannot auto-detect control block [rtt_manager]` |
| [RTM:0306](pyocd/utility/rtt_manager.py#L306) | `        0000200 W RTT 0: Failed to find control block at _SEGGER_RTT symbol address (addr=0x20000000) [rtt_manager]` |
| [RTM:0286](pyocd/utility/rtt_manager.py#L286) | `        0000220 W RTT 1: Failed to find control block at specified address (addr=0x20010000) [rtt_manager]` |
| [RTM:0320](pyocd/utility/rtt_manager.py#L320) | `        0000223 W RTT 1 Channel 0: Channel index is out of range; skipping configuration [rtt_manager]` |
| [RTM:0354](pyocd/utility/rtt_manager.py#L354) | `        0000223 E RTT 1 Channel 1: Failed to enable systemview mode: example error [rtt_manager]` |
| [GDB:0517](pyocd/gdbserver/gdbserver.py#L517) | `        0000220 D Server 1: Failed to start RTT server: example error [gdbserver]` |
| [GDB:0517](pyocd/gdbserver/gdbserver.py#L517) | `        0000223 D Server 1: Failed to configure RTT channels: example error [gdbserver]` |

Server 0 starts RTT channel 0 and listens for GDB clients

| Source | Log message |
| --- | --- |
| [RTM:0221](pyocd/utility/rtt_manager.py#L221) | `0000200 D RTT 0: Started [rtt_manager]` |
| [RTM:0303](pyocd/utility/rtt_manager.py#L303) | `0000201 D RTT 0: Control block found via _SEGGER_RTT symbol lookup (addr=0x20000000) [rtt_manager]` |
| [RTM:0343](pyocd/utility/rtt_manager.py#L343) | `0000202 I RTT 0 Channel 0: Configured (mode=server, port=5050) [rtt_manager]` |
| [GDB:0817](pyocd/gdbserver/gdbserver.py#L817) | `0000204 I Server 0: Listening on port 3333 [gdbserver]` |

Server 1 starts RTT and SystemView channels and listens for GDB clients

| Source | Log message |
| --- | --- |
| [RTM:0221](pyocd/utility/rtt_manager.py#L221) | `0000220 D RTT 1: Started [rtt_manager]` |
| [RTM:0280](pyocd/utility/rtt_manager.py#L280) | `0000221 D RTT 1: Control block found at specified address (addr=0x20010000) [rtt_manager]` |
| [RTM:0343](pyocd/utility/rtt_manager.py#L343) | `0000222 I RTT 1 Channel 0: Configured (mode=server, port=5051) [rtt_manager]` |
| [RTM:0352](pyocd/utility/rtt_manager.py#L352) | `0000223 I RTT 1 Channel 1: Configured (mode=systemview) [rtt_manager]` |
| [GDB:0817](pyocd/gdbserver/gdbserver.py#L817) | `0000224 I Server 1: Listening on port 3334 [gdbserver]` |
| [RTT:0270](pyocd/utility/rtt_server.py#L270) | `0000225 D RTT 1 Channel 1: Sending SystemView START command [rtt_server]` |

A STDIO socket consumer connects to core 1

| Source | Log message |
| --- | --- |
| [TCP:0097](pyocd/utility/server.py#L97) | `0000350 D STDIO 1: Client connected [server]` |
| [RTT:0393](pyocd/utility/rtt_server.py#L393) | `        0000500 D RTT 1 Channel 0: Failed to read up channel: example error [rtt_server]` |
| [GDB:0663](pyocd/gdbserver/gdbserver.py#L663) | `        0000500 W Server 1: Failed to poll RTT: example error [gdbserver]` |
| [GDB:0659](pyocd/gdbserver/gdbserver.py#L659) | `        0000520 I Server 1: RTT polling recovered after error [gdbserver]` |
| [RTT:0413](pyocd/utility/rtt_server.py#L413) | `        0000500 D RTT 1 Channel 0: Failed to write down channel: example error [rtt_server]` |
| [GDB:0663](pyocd/gdbserver/gdbserver.py#L663) | `        0000500 W Server 1: Failed to poll RTT: example error [gdbserver]` |
| [GDB:0659](pyocd/gdbserver/gdbserver.py#L659) | `        0000520 I Server 1: RTT polling recovered after error [gdbserver]` |
| [RTT:0400](pyocd/utility/rtt_server.py#L400) | `        0000500 E RTT 1 Channel 0: Failed to write to channel worker: example error [rtt_server]` |
| [RTT:0407](pyocd/utility/rtt_server.py#L407) | `        0000500 E RTT 1 Channel 0: Failed to read from channel worker: example error [rtt_server]` |
| [GDB:0666](pyocd/gdbserver/gdbserver.py#L666) | `        0000500 D Server 1: Failed to poll RTT: example error [gdbserver]` |
| [GDB:0695](pyocd/gdbserver/gdbserver.py#L695) | `        0000500 W Server 1: Failed to read or process target state: example error; retrying (timeout=5.0 s) [gdbserver]` |
| [GDB:0690](pyocd/gdbserver/gdbserver.py#L690) | `        0000520 I Server 1: Reading and processing target state recovered [gdbserver]` |
| [GDB:0695](pyocd/gdbserver/gdbserver.py#L695) | `        0000500 W Server 1: Failed to read or process target state: example error; retrying (timeout=5.0 s) [gdbserver]` |
| [GDB:0682](pyocd/gdbserver/gdbserver.py#L682) | `        0005501 E Server 1: Reading and processing target state did not recover within 5.0 s; shutting down GDB server [gdbserver]` |
| [GDB:0699](pyocd/gdbserver/gdbserver.py#L699) | `        0000500 E Server 1: Failed to read and process target state: example error [gdbserver]` |
| [STD:0109](pyocd/utility/stdio.py#L109) | `        0000500 D STDIO 1: Failed to write to telnet server (port=4444): example error [stdio]` |
| [STD:0274](pyocd/utility/stdio.py#L274) | `        0000500 D STDIO 0: Failed to read console input: example error; reader thread exiting [stdio]` |

Client 0-1 connects and negotiates GDB features and all-stop mode

| Source | Log message |
| --- | --- |
| [PKT:0133](pyocd/gdbserver/packet_io.py#L133) | `0003300 D Client 0-1: Packet I/O thread started [packet_io]` |
| [GDB:0184](pyocd/gdbserver/gdbserver.py#L184) | `0003301 I Client 0-1: Connected on port 3333 (remote=localhost:51000) [gdbserver]` |
| [GDB:0185](pyocd/gdbserver/gdbserver.py#L185) | `0003301 D Client 0-1: Thread started [gdbserver]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003305 D Client 0-1: Received data (len=55): b'$qSupported:qXfer:features:read+;qXfer:threads:read+#78' [packet_io]` |
| [PKT:0238](pyocd/gdbserver/packet_io.py#L238) | `0003305 D Client 0-1: Sent ACK/NACK: b'+' [packet_io]` |
| [GDB:1627](pyocd/gdbserver/gdbserver.py#L1627) | `0003305 D Client 0-1: Command: Query supported features (gdb_features=[b'qXfer:features:read+', b'qXfer:threads:read+']): [b'qXfer:features:read+', b'QStartNoAckMode+', b'qXfer:threads:read+', b'QNonStop+', b'PacketSize=800', b'qXfer:memory-map:read+'] [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0003305 D Client 0-1: Sending packet (len=109): b'$qXfer:features:read+;QStartNoAckMode+;qXfer:threads:read+;QNonStop+;PacketSize=800;qXfer:memory-map:read+#28' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003305 D Client 0-1: Received data (len=1): b'+' [packet_io]` |
| [PKT:0190](pyocd/gdbserver/packet_io.py#L190) | `0003305 D Client 0-1: Received ACK/NACK: b'+' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003310 D Client 0-1: Received data (len=19): b'$QStartNoAckMode#b0' [packet_io]` |
| [PKT:0238](pyocd/gdbserver/packet_io.py#L238) | `0003310 D Client 0-1: Sent ACK/NACK: b'+' [packet_io]` |
| [GDB:1794](pyocd/gdbserver/gdbserver.py#L1794) | `0003310 D Client 0-1: Command: General set StartNoAckMode [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0003310 D Client 0-1: Sending packet (len=6): b'$OK#9a' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003310 D Client 0-1: Received data (len=1): b'+' [packet_io]` |
| [PKT:0190](pyocd/gdbserver/packet_io.py#L190) | `0003310 D Client 0-1: Received ACK/NACK: b'+' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003315 D Client 0-1: Received data (len=14): b'$QNonStop:0#8c' [packet_io]` |
| [GDB:1803](pyocd/gdbserver/gdbserver.py#L1803) | `0003315 D Client 0-1: Command: General set NonStop=False [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0003315 D Client 0-1: Sending packet (len=6): b'$OK#9a' [packet_io]` |

Client 0-1 queries the target, selects a thread, and reads the stop reason

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003320 D Client 0-1: Received data (len=13): b'$qAttached#8f' [packet_io]` |
| [GDB:1650](pyocd/gdbserver/gdbserver.py#L1650) | `0003320 D Client 0-1: Command: Query attached: 1 [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0003320 D Client 0-1: Sending packet (len=5): b'$1#31' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003322 D Client 0-1: Received data (len=12): b'$qOffsets#4b' [packet_io]` |
| [GDB:1663](pyocd/gdbserver/gdbserver.py#L1663) | `0003322 D Client 0-1: Command: Query offsets: Text=0;Data=0;Bss=0 [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0003322 D Client 0-1: Sending packet (len=23): b'$Text=0;Data=0;Bss=0#04' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003324 D Client 0-1: Received data (len=13): b'$qSymbol::#5b' [packet_io]` |
| [GDB:1667](pyocd/gdbserver/gdbserver.py#L1667) | `0003324 D Client 0-1: Command: Query Symbol [gdbserver]` |
| [GDB:1682](pyocd/gdbserver/gdbserver.py#L1682) | `0003324 D Client 0-1: RTOS loading disabled by option [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0003324 D Client 0-1: Sending packet (len=6): b'$OK#9a' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003326 D Client 0-1: Received data (len=7): b'$Hg1#e0' [packet_io]` |
| [GDB:1069](pyocd/gdbserver/gdbserver.py#L1069) | `0003326 D Client 0-1: Command: Set thread (thread_id=0x00000001, operation=g) [gdbserver]` |
| [GDB:1073](pyocd/gdbserver/gdbserver.py#L1073) | `0003326 D Client 0-1: Command: Set thread: Threading not enabled [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0003326 D Client 0-1: Sending packet (len=6): b'$OK#9a' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003328 D Client 0-1: Received data (len=5): b'$?#3f' [packet_io]` |
| [GDB:1115](pyocd/gdbserver/gdbserver.py#L1115) | `0003328 D Client 0-1: Command: Query stop reason [gdbserver]` |
| [GDB:1937](pyocd/gdbserver/gdbserver.py#L1937) | `0003328 D Client 0-1: Stop reply: T0507:00000000;0d:00400020;0e:f1000008;0f:00010008;thread:1; [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0003328 D Client 0-1: Sending packet (len=64): b'$T0507:00000000;0d:00400020;0e:f1000008;0f:00010008;thread:1;#1f' [packet_io]` |

Client 1-1 connects and negotiates GDB features and all-stop mode

| Source | Log message |
| --- | --- |
| [PKT:0133](pyocd/gdbserver/packet_io.py#L133) | `0003350 D Client 1-1: Packet I/O thread started [packet_io]` |
| [GDB:0184](pyocd/gdbserver/gdbserver.py#L184) | `0003351 I Client 1-1: Connected on port 3334 (remote=localhost:51001) [gdbserver]` |
| [GDB:0185](pyocd/gdbserver/gdbserver.py#L185) | `0003351 D Client 1-1: Thread started [gdbserver]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003355 D Client 1-1: Received data (len=55): b'$qSupported:qXfer:features:read+;qXfer:threads:read+#78' [packet_io]` |
| [PKT:0238](pyocd/gdbserver/packet_io.py#L238) | `0003355 D Client 1-1: Sent ACK/NACK: b'+' [packet_io]` |
| [GDB:1627](pyocd/gdbserver/gdbserver.py#L1627) | `0003355 D Client 1-1: Command: Query supported features (gdb_features=[b'qXfer:features:read+', b'qXfer:threads:read+']): [b'qXfer:features:read+', b'QStartNoAckMode+', b'qXfer:threads:read+', b'QNonStop+', b'PacketSize=800', b'qXfer:memory-map:read+'] [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0003355 D Client 1-1: Sending packet (len=109): b'$qXfer:features:read+;QStartNoAckMode+;qXfer:threads:read+;QNonStop+;PacketSize=800;qXfer:memory-map:read+#28' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003355 D Client 1-1: Received data (len=1): b'+' [packet_io]` |
| [PKT:0190](pyocd/gdbserver/packet_io.py#L190) | `0003355 D Client 1-1: Received ACK/NACK: b'+' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003360 D Client 1-1: Received data (len=19): b'$QStartNoAckMode#b0' [packet_io]` |
| [PKT:0238](pyocd/gdbserver/packet_io.py#L238) | `0003360 D Client 1-1: Sent ACK/NACK: b'+' [packet_io]` |
| [GDB:1794](pyocd/gdbserver/gdbserver.py#L1794) | `0003360 D Client 1-1: Command: General set StartNoAckMode [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0003360 D Client 1-1: Sending packet (len=6): b'$OK#9a' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003360 D Client 1-1: Received data (len=1): b'+' [packet_io]` |
| [PKT:0190](pyocd/gdbserver/packet_io.py#L190) | `0003360 D Client 1-1: Received ACK/NACK: b'+' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003365 D Client 1-1: Received data (len=14): b'$QNonStop:0#8c' [packet_io]` |
| [GDB:1803](pyocd/gdbserver/gdbserver.py#L1803) | `0003365 D Client 1-1: Command: General set NonStop=False [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0003365 D Client 1-1: Sending packet (len=6): b'$OK#9a' [packet_io]` |

Client 1-1 queries the target, selects a thread, and reads the stop reason

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003370 D Client 1-1: Received data (len=13): b'$qAttached#8f' [packet_io]` |
| [GDB:1650](pyocd/gdbserver/gdbserver.py#L1650) | `0003370 D Client 1-1: Command: Query attached: 1 [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0003370 D Client 1-1: Sending packet (len=5): b'$1#31' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003372 D Client 1-1: Received data (len=12): b'$qOffsets#4b' [packet_io]` |
| [GDB:1663](pyocd/gdbserver/gdbserver.py#L1663) | `0003372 D Client 1-1: Command: Query offsets: Text=0;Data=0;Bss=0 [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0003372 D Client 1-1: Sending packet (len=23): b'$Text=0;Data=0;Bss=0#04' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003374 D Client 1-1: Received data (len=13): b'$qSymbol::#5b' [packet_io]` |
| [GDB:1667](pyocd/gdbserver/gdbserver.py#L1667) | `0003374 D Client 1-1: Command: Query Symbol [gdbserver]` |
| [GDB:1682](pyocd/gdbserver/gdbserver.py#L1682) | `0003374 D Client 1-1: RTOS loading disabled by option [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0003374 D Client 1-1: Sending packet (len=6): b'$OK#9a' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003376 D Client 1-1: Received data (len=7): b'$Hg1#e0' [packet_io]` |
| [GDB:1069](pyocd/gdbserver/gdbserver.py#L1069) | `0003376 D Client 1-1: Command: Set thread (thread_id=0x00000001, operation=g) [gdbserver]` |
| [GDB:1073](pyocd/gdbserver/gdbserver.py#L1073) | `0003376 D Client 1-1: Command: Set thread: Threading not enabled [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0003376 D Client 1-1: Sending packet (len=6): b'$OK#9a' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003378 D Client 1-1: Received data (len=5): b'$?#3f' [packet_io]` |
| [GDB:1115](pyocd/gdbserver/gdbserver.py#L1115) | `0003378 D Client 1-1: Command: Query stop reason [gdbserver]` |
| [GDB:1937](pyocd/gdbserver/gdbserver.py#L1937) | `0003378 D Client 1-1: Stop reply: T0507:00000000;0d:00400120;0e:f1000108;0f:00010108;thread:1; [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0003378 D Client 1-1: Sending packet (len=64): b'$T0507:00000000;0d:00400120;0e:f1000108;0f:00010108;thread:1;#22' [packet_io]` |

Secondary GDB client 0-2 connects

| Source | Log message |
| --- | --- |
| [PKT:0133](pyocd/gdbserver/packet_io.py#L133) | `0003500 D Client 0-2: Packet I/O thread started [packet_io]` |
| [GDB:0184](pyocd/gdbserver/gdbserver.py#L184) | `0003501 I Client 0-2: Connected on port 3333 (remote=localhost:52000) [gdbserver]` |
| [GDB:0185](pyocd/gdbserver/gdbserver.py#L185) | `0003501 D Client 0-2: Thread started [gdbserver]` |

Secondary GDB client 1-2 connects

| Source | Log message |
| --- | --- |
| [PKT:0133](pyocd/gdbserver/packet_io.py#L133) | `0003550 D Client 1-2: Packet I/O thread started [packet_io]` |
| [GDB:0184](pyocd/gdbserver/gdbserver.py#L184) | `0003551 I Client 1-2: Connected on port 3334 (remote=localhost:52001) [gdbserver]` |
| [GDB:0185](pyocd/gdbserver/gdbserver.py#L185) | `0003551 D Client 1-2: Thread started [gdbserver]` |
| [GDB:0834](pyocd/gdbserver/gdbserver.py#L834) | `        0003570 E Server 1: Failed to accept socket connection on port 3334: example error [gdbserver]` |
| [GDB:0868](pyocd/gdbserver/gdbserver.py#L868) | `        0003350 E Server 1: Failed to start client 1-1 on port 3334: example error [gdbserver]` |
| [GDB:0868](pyocd/gdbserver/gdbserver.py#L868) | `        0003350 E Server 1: Failed to start client 1-unknown on port 3334: example error [gdbserver]` |
| [GDB:0876](pyocd/gdbserver/gdbserver.py#L876) | `        0003350 E Server 1: Failed to stop client 1-1 on port 3334: example error [gdbserver]` |
| [GDB:0881](pyocd/gdbserver/gdbserver.py#L881) | `        0003350 E Server 1: Failed to clean up client 1-1 on port 3334: example error [gdbserver]` |
| [GDB:0888](pyocd/gdbserver/gdbserver.py#L888) | `        0003350 E Server 1: Failed to resume target after client 1-1 startup failure on port 3334: example error [gdbserver]` |
| [PKT:0201](pyocd/gdbserver/packet_io.py#L201) | `        0003355 D Client 1-1: Expected ACK/NACK, received b'$' [packet_io]` |
| [GDB:0215](pyocd/gdbserver/gdbserver.py#L215) | `        0003570 E Client 1-1: Processing failed: example error [gdbserver]` |
| [GDB:1028](pyocd/gdbserver/gdbserver.py#L1028) | `        0003650 D Client 1-1: Command: Set breakpoint (addr=0x08010120, requested_type=hardware, configured_type=hardware): Failed to accept breakpoint request [gdbserver]` |

Client 0-1 sets a hardware breakpoint

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003600 D Client 0-1: Received data (len=16): b'$Z1,8000120,2#70' [packet_io]` |
| [GDB:1026](pyocd/gdbserver/gdbserver.py#L1026) | `0003600 D Client 0-1: Command: Set breakpoint (addr=0x08000120, requested_type=hardware, configured_type=hardware) [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0003600 D Client 0-1: Sending packet (len=6): b'$OK#9a' [packet_io]` |

Client 1-1 sets a hardware breakpoint

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003650 D Client 1-1: Received data (len=16): b'$Z1,8010120,2#71' [packet_io]` |
| [GDB:1026](pyocd/gdbserver/gdbserver.py#L1026) | `0003650 D Client 1-1: Command: Set breakpoint (addr=0x08010120, requested_type=hardware, configured_type=hardware) [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0003650 D Client 1-1: Sending packet (len=6): b'$OK#9a' [packet_io]` |

Client 0-2 reads memory while the target is halted

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003700 D Client 0-2: Received data (len=15): b'$m20002000,4#51' [packet_io]` |
| [PKT:0238](pyocd/gdbserver/packet_io.py#L238) | `0003700 D Client 0-2: Sent ACK/NACK: b'+' [packet_io]` |
| [GDB:1529](pyocd/gdbserver/gdbserver.py#L1529) | `0003700 D Client 0-2: Command: Read memory (addr=0x20002000, len=4) [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0003700 D Client 0-2: Sending packet (len=12): b'$01020304#8a' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003700 D Client 0-2: Received data (len=1): b'+' [packet_io]` |
| [PKT:0190](pyocd/gdbserver/packet_io.py#L190) | `0003700 D Client 0-2: Received ACK/NACK: b'+' [packet_io]` |

Client 1-2 reads memory while the target is halted

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003750 D Client 1-2: Received data (len=15): b'$m20012000,4#52' [packet_io]` |
| [PKT:0238](pyocd/gdbserver/packet_io.py#L238) | `0003750 D Client 1-2: Sent ACK/NACK: b'+' [packet_io]` |
| [GDB:1529](pyocd/gdbserver/gdbserver.py#L1529) | `0003750 D Client 1-2: Command: Read memory (addr=0x20012000, len=4) [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0003750 D Client 1-2: Sending packet (len=12): b'$01020304#8a' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0003750 D Client 1-2: Received data (len=1): b'+' [packet_io]` |
| [PKT:0190](pyocd/gdbserver/packet_io.py#L190) | `0003750 D Client 1-2: Received ACK/NACK: b'+' [packet_io]` |
| [GDB:1537](pyocd/gdbserver/gdbserver.py#L1537) | `        0003750 D Client 1-2: Command: Read memory (addr=0x20012000, len=4): Failed to read memory: example error [gdbserver]` |
| [GDB:0955](pyocd/gdbserver/gdbserver.py#L955) | `        0003750 E Client 1-2: Failed to process RSP packet b'$m20012000,4#52': example error [gdbserver]` |
| [PKT:0190](pyocd/gdbserver/packet_io.py#L190) | `        0003760 D Client 1-2: Received ACK/NACK: b'-' [packet_io]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `        0003760 D Client 1-2: Sending packet (len=12): b'$01020304#8a' [packet_io]` |
| [PKT:0238](pyocd/gdbserver/packet_io.py#L238) | `        0003760 D Client 1-2: Sent ACK/NACK: b'-' [packet_io]` |

Client 0-1 continues target execution

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0004000 D Client 0-1: Received data (len=5): b'$c#63' [packet_io]` |
| [GDB:1165](pyocd/gdbserver/gdbserver.py#L1165) | `0004000 D Client 0-1: Command: Continue [gdbserver]` |
| [GDB:1168](pyocd/gdbserver/gdbserver.py#L1168) | `0004000 D Client 0-1: Target resumed [gdbserver]` |

Client 1-1 continues target execution

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0004050 D Client 1-1: Received data (len=5): b'$c#63' [packet_io]` |
| [GDB:1165](pyocd/gdbserver/gdbserver.py#L1165) | `0004050 D Client 1-1: Command: Continue [gdbserver]` |
| [GDB:1168](pyocd/gdbserver/gdbserver.py#L1168) | `0004050 D Client 1-1: Target resumed [gdbserver]` |

Client 0-2 reads memory while the target is running

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0005000 D Client 0-2: Received data (len=15): b'$m20002000,4#51' [packet_io]` |
| [PKT:0238](pyocd/gdbserver/packet_io.py#L238) | `0005000 D Client 0-2: Sent ACK/NACK: b'+' [packet_io]` |
| [GDB:1529](pyocd/gdbserver/gdbserver.py#L1529) | `0005000 D Client 0-2: Command: Read memory (addr=0x20002000, len=4) [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0005000 D Client 0-2: Sending packet (len=12): b'$01020304#8a' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0005000 D Client 0-2: Received data (len=1): b'+' [packet_io]` |
| [PKT:0190](pyocd/gdbserver/packet_io.py#L190) | `0005000 D Client 0-2: Received ACK/NACK: b'+' [packet_io]` |

Client 1-2 reads memory while the target is running

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0005005 D Client 1-2: Received data (len=15): b'$m20012000,4#52' [packet_io]` |
| [PKT:0238](pyocd/gdbserver/packet_io.py#L238) | `0005005 D Client 1-2: Sent ACK/NACK: b'+' [packet_io]` |
| [GDB:1529](pyocd/gdbserver/gdbserver.py#L1529) | `0005005 D Client 1-2: Command: Read memory (addr=0x20012000, len=4) [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0005005 D Client 1-2: Sending packet (len=12): b'$01020304#8a' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0005005 D Client 1-2: Received data (len=1): b'+' [packet_io]` |
| [PKT:0190](pyocd/gdbserver/packet_io.py#L190) | `0005005 D Client 1-2: Received ACK/NACK: b'+' [packet_io]` |
| [GDB:1234](pyocd/gdbserver/gdbserver.py#L1234) | `        0005060 W Client 1-1: Failed to read or process target state: example error; retrying (timeout=5.0 s) [gdbserver]` |
| [GDB:1225](pyocd/gdbserver/gdbserver.py#L1225) | `        0005080 I Client 1-1: Reading and processing target state recovered [gdbserver]` |
| [GDB:1234](pyocd/gdbserver/gdbserver.py#L1234) | `        0005060 W Client 1-1: Failed to read or process target state: example error; retrying (timeout=5.0 s) [gdbserver]` |
| [GDB:1251](pyocd/gdbserver/gdbserver.py#L1251) | `        0010061 E Client 1-1: Reading and processing target state did not recover within 5.0 s; reporting synthetic S0b (SIGSEGV) [gdbserver]` |
| [GDB:1244](pyocd/gdbserver/gdbserver.py#L1244) | `        0005060 W Client 1-1: Failed to process target execution state: example error [gdbserver]` |
| [GDB:1208](pyocd/gdbserver/gdbserver.py#L1208) | `        0006050 E Client 1-1: Failed to halt target: example error; reporting synthetic S02 (SIGINT) [gdbserver]` |
| [GDB:1291](pyocd/gdbserver/gdbserver.py#L1291) | `        0006150 D Client 1-1: Ctrl-C received during step [gdbserver]` |

Client 0-1 interrupts target execution

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0006000 D Client 0-1: Received data (len=1): b'\x03' [packet_io]` |
| [GDB:1196](pyocd/gdbserver/gdbserver.py#L1196) | `0006000 D Client 0-1: Ctrl-C received; halting target [gdbserver]` |
| [GDB:1937](pyocd/gdbserver/gdbserver.py#L1937) | `0006000 D Client 0-1: Stop reply: T0207:00000000;0d:00400020;0e:f1000008;0f:00010008;thread:1; [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0006000 D Client 0-1: Sending packet (len=64): b'$T0207:00000000;0d:00400020;0e:f1000008;0f:00010008;thread:1;#1c' [packet_io]` |

Client 1-1 interrupts target execution

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0006050 D Client 1-1: Received data (len=1): b'\x03' [packet_io]` |
| [GDB:1196](pyocd/gdbserver/gdbserver.py#L1196) | `0006050 D Client 1-1: Ctrl-C received; halting target [gdbserver]` |
| [GDB:1937](pyocd/gdbserver/gdbserver.py#L1937) | `0006050 D Client 1-1: Stop reply: T0207:00000000;0d:00400120;0e:f1000108;0f:00010108;thread:1; [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0006050 D Client 1-1: Sending packet (len=64): b'$T0207:00000000;0d:00400120;0e:f1000108;0f:00010108;thread:1;#1f' [packet_io]` |

Client 0-1 performs a single-step

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0006100 D Client 0-1: Received data (len=5): b'$s#73' [packet_io]` |
| [GDB:1286](pyocd/gdbserver/gdbserver.py#L1286) | `0006100 D Client 0-1: Command: Step [gdbserver]` |
| [GDB:1937](pyocd/gdbserver/gdbserver.py#L1937) | `0006101 D Client 0-1: Stop reply: T0507:00000000;0d:00400020;0e:f1000008;0f:02010008;thread:1; [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0006101 D Client 0-1: Sending packet (len=64): b'$T0507:00000000;0d:00400020;0e:f1000008;0f:02010008;thread:1;#21' [packet_io]` |

Client 1-1 performs a single-step

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0006150 D Client 1-1: Received data (len=5): b'$s#73' [packet_io]` |
| [GDB:1286](pyocd/gdbserver/gdbserver.py#L1286) | `0006150 D Client 1-1: Command: Step [gdbserver]` |
| [GDB:1937](pyocd/gdbserver/gdbserver.py#L1937) | `0006151 D Client 1-1: Stop reply: T0507:00000000;0d:00400120;0e:f1000108;0f:02010108;thread:1; [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0006151 D Client 1-1: Sending packet (len=64): b'$T0507:00000000;0d:00400120;0e:f1000108;0f:02010108;thread:1;#24' [packet_io]` |

Client 0-2 reads memory after single-stepping

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0006200 D Client 0-2: Received data (len=15): b'$m20002000,4#51' [packet_io]` |
| [PKT:0238](pyocd/gdbserver/packet_io.py#L238) | `0006200 D Client 0-2: Sent ACK/NACK: b'+' [packet_io]` |
| [GDB:1529](pyocd/gdbserver/gdbserver.py#L1529) | `0006200 D Client 0-2: Command: Read memory (addr=0x20002000, len=4) [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0006200 D Client 0-2: Sending packet (len=12): b'$01020304#8a' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0006200 D Client 0-2: Received data (len=1): b'+' [packet_io]` |
| [PKT:0190](pyocd/gdbserver/packet_io.py#L190) | `0006200 D Client 0-2: Received ACK/NACK: b'+' [packet_io]` |

Client 1-2 reads memory after single-stepping

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0006250 D Client 1-2: Received data (len=15): b'$m20012000,4#52' [packet_io]` |
| [PKT:0238](pyocd/gdbserver/packet_io.py#L238) | `0006250 D Client 1-2: Sent ACK/NACK: b'+' [packet_io]` |
| [GDB:1529](pyocd/gdbserver/gdbserver.py#L1529) | `0006250 D Client 1-2: Command: Read memory (addr=0x20012000, len=4) [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0006250 D Client 1-2: Sending packet (len=12): b'$01020304#8a' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0006250 D Client 1-2: Received data (len=1): b'+' [packet_io]` |
| [PKT:0190](pyocd/gdbserver/packet_io.py#L190) | `0006250 D Client 1-2: Received ACK/NACK: b'+' [packet_io]` |

Client 0-1 continues target execution again

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0007000 D Client 0-1: Received data (len=5): b'$c#63' [packet_io]` |
| [GDB:1165](pyocd/gdbserver/gdbserver.py#L1165) | `0007000 D Client 0-1: Command: Continue [gdbserver]` |
| [GDB:1168](pyocd/gdbserver/gdbserver.py#L1168) | `0007000 D Client 0-1: Target resumed [gdbserver]` |

Client 1-1 continues target execution again

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0007050 D Client 1-1: Received data (len=5): b'$c#63' [packet_io]` |
| [GDB:1165](pyocd/gdbserver/gdbserver.py#L1165) | `0007050 D Client 1-1: Command: Continue [gdbserver]` |
| [GDB:1168](pyocd/gdbserver/gdbserver.py#L1168) | `0007050 D Client 1-1: Target resumed [gdbserver]` |

Both targets halt at their breakpoints and the primary clients receive stop replies

| Source | Log message |
| --- | --- |
| [GDB:1222](pyocd/gdbserver/gdbserver.py#L1222) | `0008970 D Client 0-1: Target halted (pc=0x08000120) [gdbserver]` |
| [GDB:1937](pyocd/gdbserver/gdbserver.py#L1937) | `0008970 D Client 0-1: Stop reply: T0507:00000000;0d:00400020;0e:f1000008;0f:20010008;thread:1; [gdbserver]` |
| [GDB:1222](pyocd/gdbserver/gdbserver.py#L1222) | `0008970 D Client 1-1: Target halted (pc=0x08010120) [gdbserver]` |
| [GDB:1937](pyocd/gdbserver/gdbserver.py#L1937) | `0008970 D Client 1-1: Stop reply: T0507:00000000;0d:00400120;0e:f1000108;0f:20010108;thread:1; [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0008970 D Client 0-1: Sending packet (len=64): b'$T0507:00000000;0d:00400020;0e:f1000008;0f:20010008;thread:1;#21' [packet_io]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0008970 D Client 1-1: Sending packet (len=64): b'$T0507:00000000;0d:00400120;0e:f1000108;0f:20010108;thread:1;#24' [packet_io]` |

Client 0-2 reads memory after the breakpoint halt

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0009000 D Client 0-2: Received data (len=15): b'$m20002000,4#51' [packet_io]` |
| [PKT:0238](pyocd/gdbserver/packet_io.py#L238) | `0009000 D Client 0-2: Sent ACK/NACK: b'+' [packet_io]` |
| [GDB:1529](pyocd/gdbserver/gdbserver.py#L1529) | `0009000 D Client 0-2: Command: Read memory (addr=0x20002000, len=4) [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0009000 D Client 0-2: Sending packet (len=12): b'$01020304#8a' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0009000 D Client 0-2: Received data (len=1): b'+' [packet_io]` |
| [PKT:0190](pyocd/gdbserver/packet_io.py#L190) | `0009000 D Client 0-2: Received ACK/NACK: b'+' [packet_io]` |

Client 1-2 reads memory after the breakpoint halt

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0009005 D Client 1-2: Received data (len=15): b'$m20012000,4#52' [packet_io]` |
| [PKT:0238](pyocd/gdbserver/packet_io.py#L238) | `0009005 D Client 1-2: Sent ACK/NACK: b'+' [packet_io]` |
| [GDB:1529](pyocd/gdbserver/gdbserver.py#L1529) | `0009005 D Client 1-2: Command: Read memory (addr=0x20012000, len=4) [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0009005 D Client 1-2: Sending packet (len=12): b'$01020304#8a' [packet_io]` |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0009005 D Client 1-2: Received data (len=1): b'+' [packet_io]` |
| [PKT:0190](pyocd/gdbserver/packet_io.py#L190) | `0009005 D Client 1-2: Received ACK/NACK: b'+' [packet_io]` |

Client 0-1 removes its hardware breakpoint

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0009050 D Client 0-1: Received data (len=16): b'$z1,8000120,2#90' [packet_io]` |
| [GDB:1031](pyocd/gdbserver/gdbserver.py#L1031) | `0009050 D Client 0-1: Command: Clear breakpoint (addr=0x08000120, requested_type=hardware) [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0009050 D Client 0-1: Sending packet (len=6): b'$OK#9a' [packet_io]` |

Client 1-1 removes its hardware breakpoint

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0009060 D Client 1-1: Received data (len=16): b'$z1,8010120,2#91' [packet_io]` |
| [GDB:1031](pyocd/gdbserver/gdbserver.py#L1031) | `0009060 D Client 1-1: Command: Clear breakpoint (addr=0x08010120, requested_type=hardware) [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0009060 D Client 1-1: Sending packet (len=6): b'$OK#9a' [packet_io]` |

Secondary GDB client 0-2 disconnects

| Source | Log message |
| --- | --- |
| [PKT:0143](pyocd/gdbserver/packet_io.py#L143) | `0009200 D Client 0-2: Connection closed by peer [packet_io]` |
| [PKT:0165](pyocd/gdbserver/packet_io.py#L165) | `0009200 D Client 0-2: Packet I/O thread exited [packet_io]` |
| [GDB:0197](pyocd/gdbserver/gdbserver.py#L197) | `0009201 D Client 0-2: Connection closed [gdbserver]` |
| [GDB:0217](pyocd/gdbserver/gdbserver.py#L217) | `0009201 D Client 0-2: Thread stopping [gdbserver]` |
| [GDB:0917](pyocd/gdbserver/gdbserver.py#L917) | `0009201 D Client 0-2: Removing from session list [gdbserver]` |
| [GDB:0232](pyocd/gdbserver/gdbserver.py#L232) | `0009201 I Client 0-2: Disconnected [gdbserver]` |

Secondary GDB client 1-2 disconnects

| Source | Log message |
| --- | --- |
| [PKT:0143](pyocd/gdbserver/packet_io.py#L143) | `0009250 D Client 1-2: Connection closed by peer [packet_io]` |
| [PKT:0165](pyocd/gdbserver/packet_io.py#L165) | `0009250 D Client 1-2: Packet I/O thread exited [packet_io]` |
| [GDB:0197](pyocd/gdbserver/gdbserver.py#L197) | `0009251 D Client 1-2: Connection closed [gdbserver]` |
| [GDB:0217](pyocd/gdbserver/gdbserver.py#L217) | `0009251 D Client 1-2: Thread stopping [gdbserver]` |
| [GDB:0917](pyocd/gdbserver/gdbserver.py#L917) | `0009251 D Client 1-2: Removing from session list [gdbserver]` |
| [GDB:0232](pyocd/gdbserver/gdbserver.py#L232) | `0009251 I Client 1-2: Disconnected [gdbserver]` |

Primary GDB client 0-1 detaches

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0009300 D Client 0-1: Received data (len=5): b'$D#44' [packet_io]` |
| [GDB:0964](pyocd/gdbserver/gdbserver.py#L964) | `0009300 D Client 0-1: Command: Detach [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0009300 D Client 0-1: Sending packet (len=6): b'$OK#9a' [packet_io]` |
| [GDB:0217](pyocd/gdbserver/gdbserver.py#L217) | `0009301 D Client 0-1: Thread stopping [gdbserver]` |
| [PKT:0165](pyocd/gdbserver/packet_io.py#L165) | `0009301 D Client 0-1: Packet I/O thread exited [packet_io]` |
| [GDB:0917](pyocd/gdbserver/gdbserver.py#L917) | `0009301 D Client 0-1: Removing from session list [gdbserver]` |
| [GDB:0232](pyocd/gdbserver/gdbserver.py#L232) | `0009301 I Client 0-1: Disconnected [gdbserver]` |

Primary GDB client 1-1 detaches

| Source | Log message |
| --- | --- |
| [PKT:0147](pyocd/gdbserver/packet_io.py#L147) | `0009350 D Client 1-1: Received data (len=5): b'$D#44' [packet_io]` |
| [GDB:0964](pyocd/gdbserver/gdbserver.py#L964) | `0009350 D Client 1-1: Command: Detach [gdbserver]` |
| [PKT:0168](pyocd/gdbserver/packet_io.py#L168) | `0009350 D Client 1-1: Sending packet (len=6): b'$OK#9a' [packet_io]` |
| [GDB:0217](pyocd/gdbserver/gdbserver.py#L217) | `0009351 D Client 1-1: Thread stopping [gdbserver]` |
| [PKT:0165](pyocd/gdbserver/packet_io.py#L165) | `0009351 D Client 1-1: Packet I/O thread exited [packet_io]` |
| [GDB:0917](pyocd/gdbserver/gdbserver.py#L917) | `0009351 D Client 1-1: Removing from session list [gdbserver]` |
| [GDB:0232](pyocd/gdbserver/gdbserver.py#L232) | `0009351 I Client 1-1: Disconnected [gdbserver]` |
| [PKT:0151](pyocd/gdbserver/packet_io.py#L151) | `        0009370 W Client 1-1: Failed to receive data: example error; connection closed [packet_io]` |
| [PKT:0179](pyocd/gdbserver/packet_io.py#L179) | `        0009370 W Client 1-1: Failed to send packet: example error; connection closed [packet_io]` |
| [PKT:0158](pyocd/gdbserver/packet_io.py#L158) | `        0009370 D Client 1-1: Failed to receive data: example error [packet_io]` |
| [GDB:0974](pyocd/gdbserver/gdbserver.py#L974) | `        0009370 E Client 1-1: Command: Detach: Failed to detach: example error [gdbserver]` |
| [GDB:0282](pyocd/gdbserver/gdbserver.py#L282) | `        0009370 D Client 1-1: Failed to stop packet I/O or close socket: example error [gdbserver]` |
| [GDB:0222](pyocd/gdbserver/gdbserver.py#L222) | `        0009370 E Client 1-1: Failed to clean up connection resources: example error [gdbserver]` |
| [GDB:0228](pyocd/gdbserver/gdbserver.py#L228) | `        0009370 E Client 1-1: Failed to notify server of client detachment: example error [gdbserver]` |
| [GDB:0930](pyocd/gdbserver/gdbserver.py#L930) | `        0009370 E Client 1-1: Failed to resume target after client detachment: example error [gdbserver]` |

Server 0 shuts down

| Source | Log message |
| --- | --- |
| [GDB:0730](pyocd/gdbserver/gdbserver.py#L730) | `0009400 D Server 0: Shutdown requested; waiting for thread to exit [gdbserver]` |
| [GDB:0901](pyocd/gdbserver/gdbserver.py#L901) | `0009401 D Server 0: Exiting (port=3333) [gdbserver]` |
| [GDB:0769](pyocd/gdbserver/gdbserver.py#L769) | `0009402 D Server 0: Cleaning up [gdbserver]` |
| [GDB:0732](pyocd/gdbserver/gdbserver.py#L732) | `0009430 I Server 0: Stopped [gdbserver]` |

Server 1 shuts down and stops SystemView capture and the STDIO server

| Source | Log message |
| --- | --- |
| [GDB:0730](pyocd/gdbserver/gdbserver.py#L730) | `0009431 D Server 1: Shutdown requested; waiting for thread to exit [gdbserver]` |
| [GDB:0901](pyocd/gdbserver/gdbserver.py#L901) | `0009432 D Server 1: Exiting (port=3334) [gdbserver]` |
| [GDB:0769](pyocd/gdbserver/gdbserver.py#L769) | `0009433 D Server 1: Cleaning up [gdbserver]` |
| [RTT:0280](pyocd/utility/rtt_server.py#L280) | `0009434 D RTT 1 Channel 1: Sending SystemView STOP command [rtt_server]` |
| [TCP:0129](pyocd/utility/server.py#L129) | `0009490 I STDIO 1: Server stopped [server]` |
| [GDB:0732](pyocd/gdbserver/gdbserver.py#L732) | `0009492 I Server 1: Stopped [gdbserver]` |
| [GDB:0747](pyocd/gdbserver/gdbserver.py#L747) | `        0009493 D Client 1-1: Failed to stop: example error [gdbserver]` |
| [GDB:0754](pyocd/gdbserver/gdbserver.py#L754) | `        0009493 D Client 1-1: Failed to clean up: example error [gdbserver]` |
| [GDB:0720](pyocd/gdbserver/gdbserver.py#L720) | `        0010434 D Server 1: Failed to stop service thread: timeout expired [gdbserver]` |
| [GDB:0773](pyocd/gdbserver/gdbserver.py#L773) | `        0009493 D Server 1: Failed to clean up client sessions: example error [gdbserver]` |
| [GDB:0779](pyocd/gdbserver/gdbserver.py#L779) | `        0009493 D Server 1: Failed to stop service thread: example error [gdbserver]` |
| [GDB:0786](pyocd/gdbserver/gdbserver.py#L786) | `        0009493 D Server 1: Failed to stop RTT server: example error [gdbserver]` |
| [GDB:0795](pyocd/gdbserver/gdbserver.py#L795) | `        0009493 D Server 1: Failed to clean up semihosting: example error [gdbserver]` |
| [GDB:0804](pyocd/gdbserver/gdbserver.py#L804) | `        0009493 D Server 1: Failed to shut down stdio: example error [gdbserver]` |
| [GDB:0812](pyocd/gdbserver/gdbserver.py#L812) | `        0009493 D Server 1: Failed to close listener socket: example error [gdbserver]` |
| [STD:0126](pyocd/utility/stdio.py#L126) | `        0009493 D STDIO 1: Failed to stop telnet server (port=4444): example error [stdio]` |

SystemView generates the output SVDat file

| Source | Log message |
| --- | --- |
| [SVW:0151](pyocd/utility/systemview.py#L151) | `0009500 I SystemView: SVDat file 'C:\D\GitHub\pyOCD\pyOCD\logs_1.SVDat' generated [systemview]` |
| [SVW:0108](pyocd/utility/systemview.py#L108) | `        0009501 E SystemView: Failed to remove temporary empty SystemView file 'C:\\D\\GitHub\\pyOCD\\pyOCD\\logs_1.core1.ch1.bin' [systemview]` |
| [SVW:0111](pyocd/utility/systemview.py#L111) | `        0009501 D SystemView: No temporary SystemView files; skipping SVDat generation [systemview]` |
| [SVW:0146](pyocd/utility/systemview.py#L146) | `        0009501 E SystemView: Failed to remove SystemView file 'C:\\D\\GitHub\\pyOCD\\pyOCD\\logs_1.core1.ch1.bin' after appending [systemview]` |
| [SVW:0151](pyocd/utility/systemview.py#L151) | `        0009501 I SystemView: SVDat file 'C:\D\GitHub\pyOCD\pyOCD\logs_1.SVDat' generated [systemview]` |
| [SVW:0148](pyocd/utility/systemview.py#L148) | `        0009501 E SystemView: failed to open/write SystemView output file 'C:\D\GitHub\pyOCD\pyOCD\logs_1.SVDat': example error [systemview]` |

Additional examples: RTT configuration and trace-processing failures

| Source | Log message |
| --- | --- |
| [GDB:0416](pyocd/gdbserver/gdbserver.py#L416) | `        0000000 E Server 1: Failed to read RTT configuration: example error; RTT setup disabled [gdbserver]` |
| [GDB:0481](pyocd/gdbserver/gdbserver.py#L481) | `        0000000 D Client 1-1: Failed to flush trace: example error [gdbserver]` |
| [GDB:0488](pyocd/gdbserver/gdbserver.py#L488) | `        0000000 D Client 1-1: Failed to capture trace: example error [gdbserver]` |

Additional examples: run-control ownership, non-stop halt failure, and stop-notification failure

| Source | Log message |
| --- | --- |
| [GDB:0523](pyocd/gdbserver/gdbserver.py#L523) | `        0000000 W Client 1-2: Cannot start execution: client 1-1 owns run control [gdbserver]` |
| [GDB:0599](pyocd/gdbserver/gdbserver.py#L599) | `        0000000 E Client 1-1: Failed to halt target: example error; reporting synthetic S02 (SIGINT) [gdbserver]` |
| [GDB:0610](pyocd/gdbserver/gdbserver.py#L610) | `        0000000 E Client 1-1: Failed to send stop notification: example error [gdbserver]` |

Additional examples: server shutdown signals

| Source | Log message |
| --- | --- |
| [GDB:0734](pyocd/gdbserver/gdbserver.py#L734) | `        0000000 D Server 1: Shutdown event set [gdbserver]` |
| [GDB:0735](pyocd/gdbserver/gdbserver.py#L735) | `        0000000 I Server 1: Shutdown requested [gdbserver]` |

Additional examples: unknown RSP command and extended-mode, kill, or restart requests

| Source | Log message |
| --- | --- |
| [GDB:0943](pyocd/gdbserver/gdbserver.py#L943) | `        0000000 E Client 1-1: Unknown RSP command: 'u' [gdbserver]` |
| [GDB:0959](pyocd/gdbserver/gdbserver.py#L959) | `        0000000 D Client 1-1: Command: Extended mode [gdbserver]` |
| [GDB:0979](pyocd/gdbserver/gdbserver.py#L979) | `        0000000 D Client 1-1: Command: Kill [gdbserver]` |
| [GDB:0985](pyocd/gdbserver/gdbserver.py#L985) | `        0000000 E Client 1-1: Command: Kill: Failed to stop client: example error [gdbserver]` |
| [GDB:0989](pyocd/gdbserver/gdbserver.py#L989) | `        0000000 D Client 1-1: Command: Restart [gdbserver]` |
| [GDB:0999](pyocd/gdbserver/gdbserver.py#L999) | `        0000000 E Client 1-1: Command: Restart: Failed to reset and halt target: example error [gdbserver]` |

Additional examples: software breakpoint configuration and breakpoint request failures

| Source | Log message |
| --- | --- |
| [GDB:1012](pyocd/gdbserver/gdbserver.py#L1012) | `        0000000 D Client 1-1: Command: Set breakpoint (addr=0x08010120, requested_type=software, configured_type=software) [gdbserver]` |
| [GDB:1012](pyocd/gdbserver/gdbserver.py#L1012) | `        0000000 D Client 1-1: Command: Set breakpoint (addr=0x08010120, requested_type=software, configured_type=hardware) [gdbserver]` |
| [GDB:1015](pyocd/gdbserver/gdbserver.py#L1015) | `        0000000 D Client 1-1: Command: Set breakpoint (addr=0x08010120, requested_type=software, configured_type=software): Failed to accept breakpoint request [gdbserver]` |
| [GDB:1015](pyocd/gdbserver/gdbserver.py#L1015) | `        0000000 D Client 1-1: Command: Set breakpoint (addr=0x08010120, requested_type=software, configured_type=hardware): Failed to accept breakpoint request [gdbserver]` |
| [GDB:1019](pyocd/gdbserver/gdbserver.py#L1019) | `        0000000 D Client 1-1: Command: Clear breakpoint (addr=0x08010120, requested_type=software) [gdbserver]` |
| [GDB:1046](pyocd/gdbserver/gdbserver.py#L1046) | `        0000000 D Client 1-1: Command: Breakpoint/watchpoint: Invalid command 'Z9' [gdbserver]` |

Additional examples: setting and clearing write, read, or access watchpoints

| Source | Log message |
| --- | --- |
| [GDB:1057](pyocd/gdbserver/gdbserver.py#L1057) | `        0000000 D Client 1-1: Command: Set write watchpoint (addr=0x20012000, size=4) [gdbserver]` |
| [GDB:1057](pyocd/gdbserver/gdbserver.py#L1057) | `        0000000 D Client 1-1: Command: Set read watchpoint (addr=0x20012000, size=4) [gdbserver]` |
| [GDB:1057](pyocd/gdbserver/gdbserver.py#L1057) | `        0000000 D Client 1-1: Command: Set access watchpoint (addr=0x20012000, size=4) [gdbserver]` |
| [GDB:1059](pyocd/gdbserver/gdbserver.py#L1059) | `        0000000 D Client 1-1: Command: Set write watchpoint (addr=0x20012000, size=4): Failed to set watchpoint [gdbserver]` |
| [GDB:1059](pyocd/gdbserver/gdbserver.py#L1059) | `        0000000 D Client 1-1: Command: Set read watchpoint (addr=0x20012000, size=4): Failed to set watchpoint [gdbserver]` |
| [GDB:1059](pyocd/gdbserver/gdbserver.py#L1059) | `        0000000 D Client 1-1: Command: Set access watchpoint (addr=0x20012000, size=4): Failed to set watchpoint [gdbserver]` |
| [GDB:1062](pyocd/gdbserver/gdbserver.py#L1062) | `        0000000 D Client 1-1: Command: Clear write watchpoint (addr=0x20012000, size=4) [gdbserver]` |
| [GDB:1062](pyocd/gdbserver/gdbserver.py#L1062) | `        0000000 D Client 1-1: Command: Clear read watchpoint (addr=0x20012000, size=4) [gdbserver]` |
| [GDB:1062](pyocd/gdbserver/gdbserver.py#L1062) | `        0000000 D Client 1-1: Command: Clear access watchpoint (addr=0x20012000, size=4) [gdbserver]` |

Additional examples: invalid thread selections and thread-alive queries

| Source | Log message |
| --- | --- |
| [GDB:1077](pyocd/gdbserver/gdbserver.py#L1077) | `        0000000 D Client 1-1: Command: Set thread (thread_id=0x00000001): Invalid thread ID [gdbserver]` |
| [GDB:1093](pyocd/gdbserver/gdbserver.py#L1093) | `        0000000 D Client 1-1: Command: Set thread (thread_id=0x00000001, operation=z): Invalid thread operation [gdbserver]` |
| [GDB:1093](pyocd/gdbserver/gdbserver.py#L1093) | `        0000000 D Client 1-1: Command: Set thread (thread_id=0x00000000, operation=z): Invalid thread operation [gdbserver]` |
| [GDB:1093](pyocd/gdbserver/gdbserver.py#L1093) | `        0000000 D Client 1-1: Command: Set thread (thread_id=-1, operation=z): Invalid thread operation [gdbserver]` |
| [GDB:1108](pyocd/gdbserver/gdbserver.py#L1108) | `        0000000 D Client 1-1: Command: Is thread alive (thread_id=0x00000001): OK [gdbserver]` |
| [GDB:1111](pyocd/gdbserver/gdbserver.py#L1111) | `        0000000 D Client 1-1: Command: Is thread alive (thread_id=0x00000002): Not alive (E00) [gdbserver]` |

Additional examples: continue or step addresses are ignored

| Source | Log message |
| --- | --- |
| [GDB:1163](pyocd/gdbserver/gdbserver.py#L1163) | `        0000000 D Client 1-1: Command: Continue (addr=0x20012000): Address is ignored [gdbserver]` |
| [GDB:1284](pyocd/gdbserver/gdbserver.py#L1284) | `        0000000 D Client 1-1: Command: Step (addr=0x20012000): Address is ignored [gdbserver]` |

Additional examples: non-stop notifications, vStopped, and vCont requests or failures

| Source | Log message |
| --- | --- |
| [GDB:1306](pyocd/gdbserver/gdbserver.py#L1306) | `        0000000 D Client 1-1: Notification: Stop [gdbserver]` |
| [GDB:1324](pyocd/gdbserver/gdbserver.py#L1324) | `        0000000 D Client 1-1: Command: Query vCont actions: vCont;c;C;s;S;r;t [gdbserver]` |
| [GDB:1334](pyocd/gdbserver/gdbserver.py#L1334) | `        0000000 D Client 1-1: Command: vStopped [gdbserver]` |
| [GDB:1340](pyocd/gdbserver/gdbserver.py#L1340) | `        0000000 D Client 1-1: Command: vUnsupported: Unknown command [gdbserver]` |
| [GDB:1347](pyocd/gdbserver/gdbserver.py#L1347) | `        0000000 D Client 1-1: Command: vCont: No operations [gdbserver]` |
| [GDB:1377](pyocd/gdbserver/gdbserver.py#L1377) | `        0000000 D Client 1-1: Command: vCont (thread_id=0x00000001): No action for current thread [gdbserver]` |
| [GDB:1385](pyocd/gdbserver/gdbserver.py#L1385) | `        0000000 D Client 1-1: Command: vCont (thread_id=0x00000001, action=continue): Skipped; run control already owned [gdbserver]` |
| [GDB:1385](pyocd/gdbserver/gdbserver.py#L1385) | `        0000000 D Client 1-1: Command: vCont (thread_id=0x00000001, action=step): Skipped; run control already owned [gdbserver]` |
| [GDB:1390](pyocd/gdbserver/gdbserver.py#L1390) | `        0000000 D Client 1-1: Command: vCont (thread_id=0x00000001, action=continue) [gdbserver]` |
| [GDB:1407](pyocd/gdbserver/gdbserver.py#L1407) | `        0000000 D Client 1-1: Command: vCont (thread_id=0x00000001, action=step, start=0x08010100, end=0x08010110) [gdbserver]` |
| [GDB:1409](pyocd/gdbserver/gdbserver.py#L1409) | `        0000000 D Client 1-1: Command: vCont (thread_id=0x00000001, action=step) [gdbserver]` |
| [GDB:1432](pyocd/gdbserver/gdbserver.py#L1432) | `        0000000 E Client 1-1: Failed to send step stop notification: example error [gdbserver]` |
| [GDB:1438](pyocd/gdbserver/gdbserver.py#L1438) | `        0000000 D Client 1-1: Command: vCont (thread_id=0x00000001, action=stop) [gdbserver]` |
| [GDB:1453](pyocd/gdbserver/gdbserver.py#L1453) | `        0000000 E Client 1-1: Command: vCont (thread_id=0x00000001, action=stop): Failed to stop target: example error [gdbserver]` |
| [GDB:1457](pyocd/gdbserver/gdbserver.py#L1457) | `        0000000 E Client 1-1: Command: vCont (thread_id=0x00000001, action=stop): Failed to stop target: example error [gdbserver]` |
| [GDB:1466](pyocd/gdbserver/gdbserver.py#L1466) | `        0000000 E Client 1-1: Failed to send stop notification: example error [gdbserver]` |
| [GDB:1469](pyocd/gdbserver/gdbserver.py#L1469) | `        0000000 E Client 1-1: Command: vCont (thread_id=0x00000001, action='x'): Unsupported action [gdbserver]` |

Additional examples: flash erase, buffered flash write, and flash completion commands

| Source | Log message |
| --- | --- |
| [GDB:1479](pyocd/gdbserver/gdbserver.py#L1479) | `        0000000 D Client 1-1: Command: Flash erase [gdbserver]` |
| [GDB:1484](pyocd/gdbserver/gdbserver.py#L1484) | `        0000000 D Client 1-1: Command: Flash write (addr=0x08010100) [gdbserver]` |
| [GDB:1504](pyocd/gdbserver/gdbserver.py#L1504) | `        0000000 D Client 1-1: Command: Flash done [gdbserver]` |

Additional examples: memory writes and write failures

| Source | Log message |
| --- | --- |
| [GDB:1551](pyocd/gdbserver/gdbserver.py#L1551) | `        0000000 D Client 1-1: Command: Write memory (addr=0x20012000, len=4, encoding=hex) [gdbserver]` |
| [GDB:1560](pyocd/gdbserver/gdbserver.py#L1560) | `        0000000 D Client 1-1: Command: Write memory (addr=0x20012000, len=4, encoding=hex): Failed to write memory: example error [gdbserver]` |
| [GDB:1574](pyocd/gdbserver/gdbserver.py#L1574) | `        0000000 D Client 1-1: Command: Write memory (addr=0x20012000, len=4) [gdbserver]` |
| [GDB:1583](pyocd/gdbserver/gdbserver.py#L1583) | `        0000000 D Client 1-1: Command: Write memory (addr=0x20012000, len=4): Failed to write memory: example error [gdbserver]` |

Additional examples: reading and writing individual or general registers

| Source | Log message |
| --- | --- |
| [GDB:1589](pyocd/gdbserver/gdbserver.py#L1589) | `        0000000 D Client 1-1: Command: Read register (reg_num=0x0) [gdbserver]` |
| [GDB:1595](pyocd/gdbserver/gdbserver.py#L1595) | `        0000000 D Client 1-1: Command: Write register (reg_num=0x0, value=00000000) [gdbserver]` |
| [GDB:1600](pyocd/gdbserver/gdbserver.py#L1600) | `        0000000 D Client 1-1: Command: Read general registers [gdbserver]` |
| [GDB:1604](pyocd/gdbserver/gdbserver.py#L1604) | `        0000000 D Client 1-1: Command: Write general registers (registers_data=0000000000000000) [gdbserver]` |

Additional examples: malformed or unsupported general queries and current-thread queries

| Source | Log message |
| --- | --- |
| [GDB:1612](pyocd/gdbserver/gdbserver.py#L1612) | `        0000000 E Client 1-1: Command: General query: Malformed packet received [gdbserver]` |
| [GDB:1637](pyocd/gdbserver/gdbserver.py#L1637) | `        0000000 D Client 1-1: Command: Query Xfer:unsupported:write: Unsupported request [gdbserver]` |
| [GDB:1646](pyocd/gdbserver/gdbserver.py#L1646) | `        0000000 D Client 1-1: Command: Query current thread ID: 0x00000001 [gdbserver]` |
| [GDB:1654](pyocd/gdbserver/gdbserver.py#L1654) | `        0000000 D Client 1-1: Command: Query TStatus: Not supported [gdbserver]` |
| [GDB:1658](pyocd/gdbserver/gdbserver.py#L1658) | `        0000000 D Client 1-1: Command: Query Tf: Not supported [gdbserver]` |
| [GDB:1677](pyocd/gdbserver/gdbserver.py#L1677) | `        0000000 D Client 1-1: Command: Query Unsupported: Not supported [gdbserver]` |

Additional examples: RTOS plugin loading and GDB symbol lookup

| Source | Log message |
| --- | --- |
| [GDB:1687](pyocd/gdbserver/gdbserver.py#L1687) | `        0000000 E Client 1-1: Specified RTOS plugin 'missing_rtos' not found [gdbserver]` |
| [GDB:1692](pyocd/gdbserver/gdbserver.py#L1692) | `        0000000 D Client 1-1: Attempting to load RTOS plugins [gdbserver]` |
| [GDB:1697](pyocd/gdbserver/gdbserver.py#L1697) | `        0000000 D Client 1-1: Attempting to load RTOS plugin 'freertos' [gdbserver]` |
| [GDB:1700](pyocd/gdbserver/gdbserver.py#L1700) | `        0000000 I Client 1-1: Loaded RTOS plugin 'freertos' [gdbserver]` |
| [GDB:1704](pyocd/gdbserver/gdbserver.py#L1704) | `        0000000 E Client 1-1: Failed to load specified RTOS plugin 'freertos' [gdbserver]` |
| [GDB:1706](pyocd/gdbserver/gdbserver.py#L1706) | `        0000000 E Client 1-1: Failed to look up RTOS symbols: example error [gdbserver]` |
| [GDB:1723](pyocd/gdbserver/gdbserver.py#L1723) | `        0000000 E Client 1-1: Connection closed during GDB lookup of symbol 'pxCurrentTCB' [gdbserver]` |
| [GDB:1731](pyocd/gdbserver/gdbserver.py#L1731) | `        0000000 E Client 1-1: Unexpected response from GDB for symbol value request [gdbserver]` |
| [GDB:1738](pyocd/gdbserver/gdbserver.py#L1738) | `        0000000 E Client 1-1: GDB symbol reply has an unexpected name (expected='pxCurrentTCB', received='unexpected_symbol') [gdbserver]` |
| [GDB:1747](pyocd/gdbserver/gdbserver.py#L1747) | `        0000000 E Client 1-1: Failed to get value of symbol 'pxCurrentTCB' from GDB: example error [gdbserver]` |

Additional examples: remote commands and command execution failures

| Source | Log message |
| --- | --- |
| [GDB:1754](pyocd/gdbserver/gdbserver.py#L1754) | `        0000000 D Client 1-1: Command: Remote (cmd='help') [gdbserver]` |
| [GDB:1770](pyocd/gdbserver/gdbserver.py#L1770) | `        0000000 E Client 1-1: Command: Remote (cmd='help'): Failed to execute command (transfer error): example error [gdbserver]` |
| [GDB:1774](pyocd/gdbserver/gdbserver.py#L1774) | `        0000000 E Client 1-1: Command: Remote (cmd='help'): Failed to execute command (unexpected error): example error [gdbserver]` |

Additional examples: rejected or unsupported general-set requests

| Source | Log message |
| --- | --- |
| [GDB:1800](pyocd/gdbserver/gdbserver.py#L1800) | `        0000000 D Client 1-1: Command: General set NonStop: Rejected; GDB File-I/O requires all-stop mode [gdbserver]` |
| [GDB:1807](pyocd/gdbserver/gdbserver.py#L1807) | `        0000000 D Client 1-1: Command: General set Unsupported: Not supported [gdbserver]` |

Additional examples: XML transfer requests, invalid annexes, and out-of-bounds offsets

| Source | Log message |
| --- | --- |
| [GDB:1817](pyocd/gdbserver/gdbserver.py#L1817) | `        0000000 D Client 1-1: Command: Query Xfer:memory-map:read (annex='unexpected.xml', offset=0, size=4): Annex not empty [gdbserver]` |
| [GDB:1824](pyocd/gdbserver/gdbserver.py#L1824) | `        0000000 D Client 1-1: Command: Query Xfer:features:read (annex='unexpected.xml', offset=0, size=4): Unsupported annex [gdbserver]` |
| [GDB:1828](pyocd/gdbserver/gdbserver.py#L1828) | `        0000000 D Client 1-1: Command: Query Xfer:threads:read (annex='unexpected.xml', offset=0, size=4): Annex not empty [gdbserver]` |
| [GDB:1833](pyocd/gdbserver/gdbserver.py#L1833) | `        0000000 D Client 1-1: Command: Query Xfer:unsupported:read (annex='unexpected.xml', offset=0, size=4): Unsupported XML query [gdbserver]` |
| [GDB:1841](pyocd/gdbserver/gdbserver.py#L1841) | `        0000000 E Client 1-1: Command: Query Xfer:features:read (annex='target.xml', offset=4096, size=4): Offset out of bounds [gdbserver]` |
| [GDB:1855](pyocd/gdbserver/gdbserver.py#L1855) | `        0000000 D Client 1-1: Command: Query Xfer:features:read (annex='target.xml', offset=0, size=4): <?xm [gdbserver]` |

Additional examples: GDB File-I/O semihosting requests and responses

| Source | Log message |
| --- | --- |
| [GDB:1866](pyocd/gdbserver/gdbserver.py#L1866) | `        0000000 D Client 1-1: Syscall request: write,1,20000000,4 [gdbserver]` |
| [GDB:1868](pyocd/gdbserver/gdbserver.py#L1868) | `        0000000 D Server 1: Skipping GDB syscall write,1,20000000,4: no client assigned to this semihosting operation [gdbserver]` |
| [GDB:1887](pyocd/gdbserver/gdbserver.py#L1887) | `        0000000 E Client 1-1: Connection closed during syscall [gdbserver]` |
| [GDB:1896](pyocd/gdbserver/gdbserver.py#L1896) | `        0000000 D Client 1-1: Syscall response received: b'$F4,0#d6' [gdbserver]` |
| [GDB:1915](pyocd/gdbserver/gdbserver.py#L1915) | `        0000000 W Client 1-1: Detach received during syscall [gdbserver]` |

Additional examples: reset events and changes to semihosting enablement

| Source | Log message |
| --- | --- |
| [GDB:1979](pyocd/gdbserver/gdbserver.py#L1979) | `        0000000 D Server 1: POST_RESET event received [gdbserver]` |
| [GDB:2000](pyocd/gdbserver/gdbserver.py#L2000) | `        0000000 I Server 1: Semihosting enabled [gdbserver]` |
| [GDB:2000](pyocd/gdbserver/gdbserver.py#L2000) | `        0000000 I Server 1: Semihosting disabled [gdbserver]` |

Additional example: packet I/O drops a reply

| Source | Log message |
| --- | --- |
| [PKT:0114](pyocd/gdbserver/packet_io.py#L114) | `        0000000 D Client 1-1: Dropping reply: b'$OK#9a' [packet_io]` |

Additional examples: RTT channel configuration validation and global configuration overrides

| Source | Log message |
| --- | --- |
| [RTM:0065](pyocd/utility/rtt_manager.py#L65) | `        0000000 W RTT 1: Channel configuration missing channel number; channel disabled [rtt_manager]` |
| [RTM:0068](pyocd/utility/rtt_manager.py#L68) | `        0000000 W RTT 1 Channel 0: Already configured; skipping duplicate [rtt_manager]` |
| [RTM:0072](pyocd/utility/rtt_manager.py#L72) | `        0000000 W RTT 1 Channel 0: Configuration missing mode; channel disabled [rtt_manager]` |
| [RTM:0076](pyocd/utility/rtt_manager.py#L76) | `        0000000 W RTT 1 Channel 0: Unsupported mode 'unsupported'; channel disabled [rtt_manager]` |
| [RTM:0082](pyocd/utility/rtt_manager.py#L82) | `        0000000 W RTT 1 Channel 0: Configuration missing port for server mode; channel disabled [rtt_manager]` |
| [RTM:0082](pyocd/utility/rtt_manager.py#L82) | `        0000000 W RTT 1 Channel 0: Configuration missing port for systemview-server mode; channel disabled [rtt_manager]` |
| [RTM:0086](pyocd/utility/rtt_manager.py#L86) | `        0000000 W RTT 1 Channel 1: Port 5051 is already in use for server mode on channel 0; channel disabled [rtt_manager]` |
| [RTM:0086](pyocd/utility/rtt_manager.py#L86) | `        0000000 W RTT 1 Channel 1: Port 5051 is already in use for systemview-server mode on channel 0; channel disabled [rtt_manager]` |
| [RTM:0109](pyocd/utility/rtt_manager.py#L109) | `        0000000 W RTT 1 Channel 0: Directory for file-out 'C:\\D\\GitHub\\pyOCD\\pyOCD\\missing-dir' for file mode does not exist; channel out disabled [rtt_manager]` |
| [RTM:0113](pyocd/utility/rtt_manager.py#L113) | `        0000000 W RTT 1 Channel 0: File-in 'C:\\D\\GitHub\\pyOCD\\pyOCD\\missing-rtt.in' for file mode does not exist; channel in disabled [rtt_manager]` |
| [RTM:0166](pyocd/utility/rtt_manager.py#L166) | `        0000000 D RTT 1 Channel 0: Core-specific configuration used; skipping global channel configuration [rtt_manager]` |

Additional examples: RTT startup, control-block discovery, and channel configuration prerequisites

| Source | Log message |
| --- | --- |
| [RTM:0255](pyocd/utility/rtt_manager.py#L255) | `        0000000 D RTT 1: No RTT configuration; RTT disabled [rtt_manager]` |
| [RTM:0259](pyocd/utility/rtt_manager.py#L259) | `        0000000 W RTT 1: No channels configured; RTT disabled [rtt_manager]` |
| [RTM:0263](pyocd/utility/rtt_manager.py#L263) | `        0000000 W RTT 1: Already running; start_server() call ignored [rtt_manager]` |
| [RTM:0272](pyocd/utility/rtt_manager.py#L272) | `        0000000 W RTT 1: Control block configuration is missing address while auto-detect is disabled; RTT disabled [rtt_manager]` |
| [RTM:0278](pyocd/utility/rtt_manager.py#L278) | `        0000000 D RTT 1: Control block found via memory scan (addr=0x20010000, size=0x1000) [rtt_manager]` |
| [RTM:0284](pyocd/utility/rtt_manager.py#L284) | `        0000000 W RTT 1: Failed to find control block via memory scan (addr=0x20010000, size=0x1000) [rtt_manager]` |
| [RTM:0291](pyocd/utility/rtt_manager.py#L291) | `        0000000 D RTT 1: Control block found via auto-detect memory scan in default memory region [rtt_manager]` |
| [RTM:0294](pyocd/utility/rtt_manager.py#L294) | `        0000000 W RTT 1: Failed to find control block via auto-detect memory scan [rtt_manager]` |
| [RTM:0313](pyocd/utility/rtt_manager.py#L313) | `        0000000 W RTT 1: Not started; cannot configure channels [rtt_manager]` |
| [RTM:0323](pyocd/utility/rtt_manager.py#L323) | `        0000000 W RTT 1 Channel 0: Already configured; skipping configuration [rtt_manager]` |
| [RTM:0328](pyocd/utility/rtt_manager.py#L328) | `        0000000 W RTT 1 Channel 0: StdioHandler is not provided; skipping configuration [rtt_manager]` |
| [RTM:0331](pyocd/utility/rtt_manager.py#L331) | `        0000000 W RTT 1 Channel 1: Stdio mode is already enabled; skipping configuration [rtt_manager]` |

Additional examples: RTT STDIO, TCP SystemView, and file channel modes

| Source | Log message |
| --- | --- |
| [RTM:0335](pyocd/utility/rtt_manager.py#L335) | `        0000000 I RTT 1 Channel 0: Configured (mode=stdio) [rtt_manager]` |
| [RTM:0338](pyocd/utility/rtt_manager.py#L338) | `        0000000 E RTT 1 Channel 0: Failed to enable stdio mode: example error [rtt_manager]` |
| [RTM:0345](pyocd/utility/rtt_manager.py#L345) | `        0000000 E RTT 1 Channel 0: Failed to enable server mode: example error [rtt_manager]` |
| [RTM:0359](pyocd/utility/rtt_manager.py#L359) | `        0000000 I RTT 1 Channel 1: Configured (mode=systemview-server, port=5051) [rtt_manager]` |
| [RTM:0361](pyocd/utility/rtt_manager.py#L361) | `        0000000 E RTT 1 Channel 1: Failed to enable systemview-server mode: example error [rtt_manager]` |
| [RTM:0368](pyocd/utility/rtt_manager.py#L368) | `        0000000 I RTT 1 Channel 0: Configured (mode=file, file-out=C:\D\GitHub\pyOCD\pyOCD\example-rtt.out, file-in=C:\D\GitHub\pyOCD\pyOCD\example-rtt.in) [rtt_manager]` |
| [RTM:0368](pyocd/utility/rtt_manager.py#L368) | `        0000000 I RTT 1 Channel 0: Configured (mode=file, file-out=C:\D\GitHub\pyOCD\pyOCD\example-rtt.out) [rtt_manager]` |
| [RTM:0368](pyocd/utility/rtt_manager.py#L368) | `        0000000 I RTT 1 Channel 0: Configured (mode=file, file-in=C:\D\GitHub\pyOCD\pyOCD\example-rtt.in) [rtt_manager]` |
| [RTM:0368](pyocd/utility/rtt_manager.py#L368) | `        0000000 I RTT 1 Channel 0: Configured (mode=file) [rtt_manager]` |
| [RTM:0370](pyocd/utility/rtt_manager.py#L370) | `        0000000 E RTT 1 Channel 0: Failed to enable file mode: example error [rtt_manager]` |
| [RTM:0372](pyocd/utility/rtt_manager.py#L372) | `        0000000 W RTT 1 Channel 0: Unsupported mode 'unsupported'; skipping configuration [rtt_manager]` |

Additional examples: SystemView STOP rejection and TCP client handshake

| Source | Log message |
| --- | --- |
| [RTT:0277](pyocd/utility/rtt_server.py#L277) | `        0000000 E RTT 1 Channel 1: No down channel configured; ignoring SystemView STOP request [rtt_server]` |
| [RTT:0313](pyocd/utility/rtt_server.py#L313) | `        0000000 D RTT 1 Channel 1: Received SystemView hello message (port=19021); connection established [rtt_server]` |
| [RTT:0319](pyocd/utility/rtt_server.py#L319) | `        0000000 D RTT 1 Channel 1: Received non-hello message from SystemView client before hello message; ignoring [rtt_server]` |

Additional examples: STDIO input failures, missing files, invalid mode, and end-of-transmission handling

| Source | Log message |
| --- | --- |
| [STD:0117](pyocd/utility/stdio.py#L117) | `        0000000 D STDIO 1: Failed to read from telnet server (port=4444): example error [stdio]` |
| [STD:0161](pyocd/utility/stdio.py#L161) | `        0000000 D STDIO 1: No input file configured [stdio]` |
| [STD:0185](pyocd/utility/stdio.py#L185) | `        0000000 D STDIO 1: No input file configured; STDIN disabled [stdio]` |
| [STD:0187](pyocd/utility/stdio.py#L187) | `        0000000 D STDIO 1: Input file 'C:\\D\\GitHub\\pyOCD\\pyOCD\\missing-stdio.in' does not exist; STDIN disabled [stdio]` |
| [STD:0345](pyocd/utility/stdio.py#L345) | `        0000000 W STDIO 1: Invalid mode 'unsupported'; defaulting to 'off' [stdio]` |
| [STD:0447](pyocd/utility/stdio.py#L447) | `        0000000 D STDIO 1: Data received after EOT (0x04); discarding [stdio]` |
| [STD:0459](pyocd/utility/stdio.py#L459) | `        0000000 D STDIO 1: EOT (0x04) detected [stdio]` |

Additional example: SystemView output file is not configured

| Source | Log message |
| --- | --- |
| [SVW:0071](pyocd/utility/systemview.py#L71) | `        0000000 D SystemView: No output file configured; cannot configure SystemView SVDat generation [systemview]` |

Additional example: stopping RTT during GDB server shutdown fails

| Source | Log message |
| --- | --- |
| [GDB:0517](pyocd/gdbserver/gdbserver.py#L517) | `        0000000 D Server 1: Failed to stop RTT server during shutdown: example error [gdbserver]` |

Additional examples: non-stop mode and special continue-thread selectors

| Source | Log message |
| --- | --- |
| [GDB:1803](pyocd/gdbserver/gdbserver.py#L1803) | `        0000000 D Client 1-1: Command: General set NonStop=True [gdbserver]` |
| [GDB:1069](pyocd/gdbserver/gdbserver.py#L1069) | `        0000000 D Client 1-1: Command: Set thread (thread_id=0x00000000, operation=c) [gdbserver]` |
| [GDB:1069](pyocd/gdbserver/gdbserver.py#L1069) | `        0000000 D Client 1-1: Command: Set thread (thread_id=-1, operation=c) [gdbserver]` |

Additional examples: target-state retries have no timeout

| Source | Log message |
| --- | --- |
| [GDB:0695](pyocd/gdbserver/gdbserver.py#L695) | `        0000000 W Server 1: Failed to read or process target state: example error; retrying (timeout=none) [gdbserver]` |
| [GDB:1234](pyocd/gdbserver/gdbserver.py#L1234) | `        0000000 W Client 1-1: Failed to read or process target state: example error; retrying (timeout=none) [gdbserver]` |

Additional example: core-specific RTT configuration overrides global configuration

| Source | Log message |
| --- | --- |
| [RTM:0166](pyocd/utility/rtt_manager.py#L166) | `        0000000 D RTT 1: Core-specific configuration used; skipping global channel configuration [rtt_manager]` |
