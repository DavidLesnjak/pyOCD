# pyOCD debugger
# Copyright (c) 2006-2020,2025 Arm Limited
# Copyright (c) 2021-2023 Chris Reed
# Copyright (c) 2022 Harper Weigle
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import platform
import threading
import queue
from typing import Optional, Tuple

from .interface import Interface
from .common import (
    filter_device_by_usage_page,
    generate_device_unique_id,
    is_known_cmsis_dap_vid_pid,
    )
from ..dap_access_api import DAPAccessIntf
from ....utility.compatibility import to_str_safe
from ....utility.timeout import Timeout

LOG = logging.getLogger(__name__)
TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)

try:
    import hid
except ImportError:
    IS_AVAILABLE = False
else:
    IS_AVAILABLE = True

# OS flags.
_IS_DARWIN = (platform.system() == 'Darwin')
_IS_WINDOWS = (platform.system() == 'Windows')

if _IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    # Define necessary Windows structures and functions for HID
    PHIDP_PREPARSED_DATA = ctypes.c_void_p

    class HIDP_CAPS(ctypes.Structure):
        _fields_ = [
            ("Usage", wintypes.USHORT),
            ("UsagePage", wintypes.USHORT),
            ("InputReportByteLength", wintypes.USHORT),
            ("OutputReportByteLength", wintypes.USHORT),
            ("FeatureReportByteLength", wintypes.USHORT),
            ("Reserved", wintypes.USHORT * 17),
            ("NumberLinkCollectionNodes", wintypes.USHORT),
            ("NumberInputButtonCaps", wintypes.USHORT),
            ("NumberInputValueCaps", wintypes.USHORT),
            ("NumberInputDataIndices", wintypes.USHORT),
            ("NumberOutputButtonCaps", wintypes.USHORT),
            ("NumberOutputValueCaps", wintypes.USHORT),
            ("NumberOutputDataIndices", wintypes.USHORT),
            ("NumberFeatureButtonCaps", wintypes.USHORT),
            ("NumberFeatureValueCaps", wintypes.USHORT),
            ("NumberFeatureDataIndices", wintypes.USHORT),
        ]

    hid_dll = ctypes.windll.hid
    kernel32_dll = ctypes.windll.kernel32

    # HidD_GetPreparsedData
    hid_dll.HidD_GetPreparsedData.argtypes = [wintypes.HANDLE, ctypes.POINTER(PHIDP_PREPARSED_DATA)]
    hid_dll.HidD_GetPreparsedData.restype = wintypes.BOOLEAN

    # HidP_GetCaps
    hid_dll.HidP_GetCaps.argtypes = [PHIDP_PREPARSED_DATA, ctypes.POINTER(HIDP_CAPS)]
    hid_dll.HidP_GetCaps.restype = ctypes.c_long # NTSTATUS

    # HidD_FreePreparsedData
    hid_dll.HidD_FreePreparsedData.argtypes = [PHIDP_PREPARSED_DATA]
    hid_dll.HidD_FreePreparsedData.restype = wintypes.BOOLEAN

    # CreateFileW
    kernel32_dll.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel32_dll.CreateFileW.restype = wintypes.HANDLE

    # CloseHandle
    kernel32_dll.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32_dll.CloseHandle.restype = wintypes.BOOL

    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 1
    FILE_SHARE_WRITE = 2
    OPEN_EXISTING = 3

elif _IS_DARWIN:
    import ctypes
    import ctypes.util

    cf = ctypes.CDLL(ctypes.util.find_library('CoreFoundation'))
    iokit = ctypes.CDLL(ctypes.util.find_library('IOKit'))

    kCFStringEncodingUTF8 = 0x08000100

    # Define CFString functions
    CFStringCreateWithCString = cf.CFStringCreateWithCString
    CFStringCreateWithCString.restype = ctypes.c_void_p
    CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]

    CFRelease = cf.CFRelease
    CFRelease.restype = None
    CFRelease.argtypes = [ctypes.c_void_p]

    # Define IOHIDDevice functions
    IOHIDDeviceGetProperty = iokit.IOHIDDeviceGetProperty
    IOHIDDeviceGetProperty.restype = ctypes.c_void_p
    IOHIDDeviceGetProperty.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

    # Define CFNumber functions
    CFNumberGetValue = cf.CFNumberGetValue
    CFNumberGetValue.restype = ctypes.c_bool
    CFNumberGetValue.argtypes = [ctypes.c_void_p, ctypes.c_long, ctypes.c_void_p]
    kCFNumberSInt32Type = 3

    # Keys for IOHIDDeviceGetProperty
    def _create_cfstring(s):
        return CFStringCreateWithCString(None, s.encode('utf-8'), kCFStringEncodingUTF8)

    kIOHIDMaxInputReportSizeKey = _create_cfstring("MaxInputReportSize")
    kIOHIDMaxOutputReportSizeKey = _create_cfstring("MaxOutputReportSize")
    kIOHIDSerialNumberKey = _create_cfstring("SerialNumber")
    kIOHIDVendorIDKey = _create_cfstring("VendorID")
    kIOHIDProductIDKey = _create_cfstring("ProductID")
    kIOHIDPrimaryUsageKey = _create_cfstring("PrimaryUsage")
    kIOHIDPrimaryUsagePageKey = _create_cfstring("PrimaryUsagePage")
    kIOHIDProductKey = _create_cfstring("Product")
    kIOHIDInterfaceNumberKey = _create_cfstring("InterfaceNumber")

    # More CoreFoundation types
    CFAllocatorRef = ctypes.c_void_p
    CFDictionaryRef = ctypes.c_void_p
    CFSetRef = ctypes.c_void_p
    CFStringRef = ctypes.c_void_p
    CFNumberRef = ctypes.c_void_p
    CFIndex = ctypes.c_long

    kCFAllocatorDefault = ctypes.c_void_p.in_dll(cf, 'kCFAllocatorDefault')
    CFStringCreateWithCString = cf.CFStringCreateWithCString
    CFRelease = cf.CFRelease
    CFNumberGetValue = cf.CFNumberGetValue
    CFDictionaryCreate = cf.CFDictionaryCreate
    CFSetGetCount = cf.CFSetGetCount
    CFSetGetValues = cf.CFSetGetValues

    # CFStringGetCString is useful for converting CFString to Python string.
    CFStringGetCString = cf.CFStringGetCString
    CFStringGetCString.restype = ctypes.c_bool
    CFStringGetCString.argtypes = [CFStringRef, ctypes.c_char_p, CFIndex, ctypes.c_uint32]

    # CFNumber
    CFNumberCreate = cf.CFNumberCreate
    CFNumberCreate.restype = CFNumberRef
    CFNumberCreate.argtypes = [CFAllocatorRef, ctypes.c_long, ctypes.c_void_p]

    # CFDictionary
    CFDictionaryCreate = cf.CFDictionaryCreate
    CFDictionaryCreate.restype = CFDictionaryRef
    CFDictionaryCreate.argtypes = [CFAllocatorRef, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), CFIndex, ctypes.c_void_p, ctypes.c_void_p]

    # CFSet
    CFSetGetCount = cf.CFSetGetCount
    CFSetGetCount.restype = CFIndex
    CFSetGetCount.argtypes = [CFSetRef]

    CFSetGetValues = cf.CFSetGetValues
    CFSetGetValues.restype = None
    CFSetGetValues.argtypes = [CFSetRef, ctypes.POINTER(ctypes.c_void_p)]

    # IOHIDManager
    IOHIDManagerCreate = iokit.IOHIDManagerCreate
    IOHIDManagerCreate.restype = ctypes.c_void_p
    IOHIDManagerCreate.argtypes = [CFAllocatorRef, ctypes.c_uint32]
    kIOHIDOptionsTypeNone = 0

    IOHIDManagerSetDeviceMatching = iokit.IOHIDManagerSetDeviceMatching
    IOHIDManagerSetDeviceMatching.restype = None
    IOHIDManagerSetDeviceMatching.argtypes = [ctypes.c_void_p, CFDictionaryRef]

    IOHIDManagerCopyDevices = iokit.IOHIDManagerCopyDevices
    IOHIDManagerCopyDevices.restype = CFSetRef
    IOHIDManagerCopyDevices.argtypes = [ctypes.c_void_p]

class HidApiUSB(Interface):
    """@brief CMSIS-DAP USB interface class using hidapi backend."""

    isAvailable = IS_AVAILABLE

    HIDAPI_MAX_PACKET_COUNT = 30

    def __init__(self, dev, info: dict):
        super().__init__()
        # Vendor page and usage_id = 2
        self.vid = info['vendor_id']
        self.pid = info['product_id']
        self.vendor_name = info['manufacturer_string'] or f"{self.vid:#06x}"
        self.product_name = info['product_string'] or f"{self.pid:#06x}"
        self.serial_number = info['serial_number'] \
                or generate_device_unique_id(self.vid, self.pid, to_str_safe(info['path']))
        self.device_info = info
        self.device = dev
        self.closed = True
        self.thread = None
        self.read_sem = threading.Semaphore(0)
        self.closed_event = threading.Event()
        self.received_data: queue.SimpleQueue[bytes] = queue.SimpleQueue()
        self._read_thread_did_exit: bool = False
        self._read_thread_exception: Optional[Exception] = None
        self.report_in_size = None
        self.report_out_size = None

    def set_packet_count(self, count):
        # hidapi for macos has an arbitrary limit on the number of packets it will queue for reading.
        # Even though we have a read thread, it doesn't hurt to limit the packet count since the limit
        # is fairly high.
        if _IS_DARWIN:
            count = min(count, self.HIDAPI_MAX_PACKET_COUNT)
        self.packet_count = count

    def open(self):
        self.report_in_size, self.report_out_size = self._get_hid_report_sizes()

        if self.report_in_size is None:
            # Fallback: set report size to 64 bytes
            LOG.warning("Could not determine IN report size for probe %s, defaulting to 64 bytes", to_str_safe(self.serial_number))
            self.report_in_size = 64

        if self.report_out_size is None:
            # No interrupt OUT endpoint. Out reports will be sent via control transfer.
            # Assuming out report size matches in report size.
            self.report_out_size = self.report_in_size

        try:
            self.device.open_path(self.device_info['path'])
        except IOError as exc:
            raise DAPAccessIntf.DeviceError("Unable to open device: " + str(exc)) from exc

        # Windows does not use the receive thread because it causes packet corruption for some reason.
        if not _IS_WINDOWS:
            # Make certain the closed event is clear.
            self.closed_event.clear()

            # Start RX thread
            self.thread = threading.Thread(target=self.rx_task)
            self.thread.daemon = True
            self.thread.start()

        self.closed = False

    def _get_hid_report_sizes(self) -> Tuple[Optional[int], Optional[int]]:
        """Get actual HID report sizes using platform-specific APIs."""
        if _IS_WINDOWS:
            return self._get_hid_report_sizes_windows()
        elif _IS_DARWIN:
            return self._get_hid_report_sizes_macos()
        else:
            # Linux and other OSes are not supported for this mechanism.
            LOG.debug("Unsupported OS for getting HID report sizes directly.")
            return None, None

    def _get_hid_report_sizes_windows(self) -> Tuple[Optional[int], Optional[int]]:
        try:
            path = to_str_safe(self.device_info['path'])
            handle = kernel32_dll.CreateFileW(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None)
        except Exception as exc:
            LOG.error("Exception opening device handle for HID report size query: %s", exc)
            return None, None

        if handle == INVALID_HANDLE_VALUE:
            LOG.debug("Failed to open device handle for HID report size query.")
            return None, None

        try:
            preparsed_data = PHIDP_PREPARSED_DATA()
            if not hid_dll.HidD_GetPreparsedData(handle, ctypes.byref(preparsed_data)):
                LOG.debug("HidD_GetPreparsedData failed.")
                return None, None

            try:
                caps = HIDP_CAPS()
                HIDP_STATUS_SUCCESS = 0x00110000
                if hid_dll.HidP_GetCaps(preparsed_data, ctypes.byref(caps)) == HIDP_STATUS_SUCCESS:
                    # The lengths include the report ID byte, which we don't use in the packet size.
                    InReportSz = caps.InputReportByteLength - 1 if caps.InputReportByteLength > 0 else None
                    OutReportSz = caps.OutputReportByteLength - 1 if caps.OutputReportByteLength > 0 else None
                    return InReportSz, OutReportSz
                else:
                    LOG.debug("HidP_GetCaps failed.")
                    return None, None
            finally:
                hid_dll.HidD_FreePreparsedData(preparsed_data)
        finally:
            kernel32_dll.CloseHandle(handle)
        return None, None

    def _get_hid_report_sizes_macos(self) -> Tuple[Optional[int], Optional[int]]:
        """@brief Find the IOHIDDeviceRef for this device and query its report sizes."""
        # The self.device object from hidapi is already created, but we can't get the handle.
        # So, we re-query IOKit to find the matching IOHIDDeviceRef.
        vid = self.vid
        pid = self.pid
        # Use the original serial number from hid.enumerate(), not the generated one.
        serial = self.device_info.get('serial_number')

        iface = self.device_info.get('interface_number')

        # Create an IOHIDManager.
        manager = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone)
        if not manager:
            LOG.debug("IOHIDManagerCreate failed")
            return None, None

        matching_dict = None
        try:
            # Create a matching dictionary for the device's VID, PID, and optionally serial/interface.
            pairs = []

            # Add VID and PID.
            vid_ref = ctypes.c_int32(vid)
            pid_ref = ctypes.c_int32(pid)
            v_vid = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, ctypes.byref(vid_ref))
            v_pid = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, ctypes.byref(pid_ref))
            pairs.append((kIOHIDVendorIDKey, v_vid))
            pairs.append((kIOHIDProductIDKey, v_pid))

            # Add serial number if available.
            v_serial = None
            if serial is not None:
                v_serial = _create_cfstring(serial)
                pairs.append((kIOHIDSerialNumberKey, v_serial))

            # Add interface number if available.
            v_iface_ref = None
            if iface is not None:
                iface_ref = ctypes.c_int32(int(iface))
                v_iface_ref = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, ctypes.byref(iface_ref))
                pairs.append((kIOHIDInterfaceNumberKey, v_iface_ref))

            num_keys = len(pairs)
            keys = (ctypes.c_void_p * num_keys)(* [k for k, _ in pairs])
            values = (ctypes.c_void_p * num_keys)(* [v for _, v in pairs])

            matching_dict = CFDictionaryCreate(kCFAllocatorDefault, keys, values, num_keys, None, None)

            # Release the objects we created.
            for _, v in pairs:
                if v:
                    CFRelease(v)

            if not matching_dict:
                LOG.debug("Failed to create matching dictionary for HID report size query")
                return None, None

            IOHIDManagerSetDeviceMatching(manager, matching_dict)

            # Get all devices matching the criteria.
            device_set = IOHIDManagerCopyDevices(manager)
            if not device_set:
                LOG.debug("IOHIDManagerCopyDevices failed")
                return None, None

            try:
                count = CFSetGetCount(device_set)
                if count == 0:
                    LOG.debug("Could not find matching IOHIDDeviceRef for %s", self.serial_number)
                    return None, None
                elif count > 1:
                    # This should only happen if we are not matching by serial number.
                    LOG.warning("Found %d matching HID devices for %s; using the first one.", count, self.serial_number)

                # Get the first device from the set.
                devices = (ctypes.c_void_p * count)()
                CFSetGetValues(device_set, devices)
                hid_device_ref = devices[0]

                if not hid_device_ref:
                    LOG.debug("Could not get IOHIDDeviceRef from device set")
                    return None, None

                # Now that we have the native handle, query the report sizes.
                input_size = None
                output_size = None

                value_ref = IOHIDDeviceGetProperty(hid_device_ref, kIOHIDMaxInputReportSizeKey)
                if value_ref:
                    val = ctypes.c_int32(0)
                    if CFNumberGetValue(value_ref, kCFNumberSInt32Type, ctypes.byref(val)):
                        input_size = val.value

                value_ref = IOHIDDeviceGetProperty(hid_device_ref, kIOHIDMaxOutputReportSizeKey)
                if value_ref:
                    val = ctypes.c_int32(0)
                    if CFNumberGetValue(value_ref, kCFNumberSInt32Type, ctypes.byref(val)):
                        output_size = val.value

                if input_size and input_size > 0:
                    input_size -= 1
                if output_size and output_size > 0:
                    output_size -= 1
                return input_size, output_size
            finally:
                CFRelease(device_set)
        finally:
            if matching_dict:
                CFRelease(matching_dict)
            CFRelease(manager)
        return None, None

    def rx_task(self):
        try:
            while not self.closed_event.is_set():
                self.read_sem.acquire()
                if not self.closed_event.is_set():
                    read_data = bytes(self.device.read(self.report_in_size))

                    # This trace log is commented out to reduce clutter, but left in to leave available
                    # when debugging rx_task issues.
                    # if TRACE.isEnabledFor(logging.DEBUG):
                    #     # Strip off trailing zero bytes to reduce clutter.
                    #     TRACE.debug("  USB RD < (%d) %s", len(read_data),
                    #                 ' '.join([f'{i:02x}' for i in read_data.rstrip(b'\x00')]))

                    self.received_data.put(read_data)
        except Exception as err:
            TRACE.debug("rx_task exception: %s", err)
            self._read_thread_exception = err
        finally:
            self._swo_thread_did_exit = True

    @staticmethod
    def get_all_connected_interfaces():
        """@brief Returns all the connected devices with CMSIS-DAP in the name.

        returns an array of HidApiUSB (Interface) objects
        """

        devices = hid.enumerate()

        boards = []

        for deviceInfo in devices:
            product_name = to_str_safe(deviceInfo['product_string'])
            known_cmsis_dap = is_known_cmsis_dap_vid_pid(deviceInfo['vendor_id'], deviceInfo['product_id'])
            if ("CMSIS-DAP" not in product_name) and (not known_cmsis_dap):
                # Check the device path as a backup. Even though we can't get the interface name from
                # hidapi, it may appear in the path. At least, it does on macOS.
                device_path = to_str_safe(deviceInfo['path'])
                if "CMSIS-DAP" not in device_path:
                    # Skip non cmsis-dap devices
                    continue

            vid = deviceInfo['vendor_id']
            pid = deviceInfo['product_id']

            # Perform device-specific filtering.
            if filter_device_by_usage_page(vid, pid, deviceInfo['usage_page']):
                continue

            try:
                dev = hid.device(vendor_id=vid, product_id=pid, path=deviceInfo['path'])
            except IOError as exc:
                LOG.debug("Failed to open USB device: %s", exc)
                continue

            # Create the USB interface object for this device.
            new_board = HidApiUSB(dev, deviceInfo)
            boards.append(new_board)

        return boards

    def write(self, data):
        """@brief Write data on the OUT endpoint associated to the HID interface"""
        if TRACE.isEnabledFor(logging.DEBUG):
            TRACE.debug("  USB OUT> (%d) %s", len(data), ' '.join([f'{i:02x}' for i in data]))
        data.extend([0] * (self.report_out_size - len(data)))
        if not _IS_WINDOWS:
            self.read_sem.release()
        self.device.write([0] + data)

    def read(self):
        """@brief Read data on the IN endpoint associated to the HID interface"""
        # Windows doesn't use the read thread, so read directly.
        if _IS_WINDOWS:
            read_data = bytes(self.device.read(self.report_in_size))

            if TRACE.isEnabledFor(logging.DEBUG):
                # Strip off trailing zero bytes to reduce clutter.
                TRACE.debug("  USB IN < (%d) %s", len(read_data),
                            ' '.join([f'{i:02x}' for i in read_data.rstrip(b'\x00')]))

            return read_data

        # Check for terminated read thread.
        if self.closed:
            return b''
        elif self._read_thread_did_exit:
            raise DAPAccessIntf.DeviceError("Probe %s read thread exited unexpectedly" % self.serial_number) from self._read_thread_exception

        try:
            read_data = self.received_data.get(True, self.DEFAULT_USB_TIMEOUT_S)
        except queue.Empty:
            raise DAPAccessIntf.DeviceError(f"Timeout reading from probe {self.serial_number}") from None

        # Trace when the higher layer actually gets a packet previously read.
        if TRACE.isEnabledFor(logging.DEBUG):
            # Strip off trailing zero bytes to reduce clutter.
            TRACE.debug("  USB RD < (%d) %s", len(read_data),
                    ' '.join([f'{i:02x}' for i in read_data.rstrip(b'\x00')]))

        return read_data

    def close(self):
        """@brief Close the interface"""
        assert not self.closed_event.is_set()

        LOG.debug("closing interface")
        self.closed = True
        if not _IS_WINDOWS:
            self.closed_event.set()
            self.read_sem.release()
            assert self.thread
            self.thread.join()
            self.thread = None

            # Clear closed event, recreate read sem and received data deque so they
            # are cleared and ready if we're re-opened.
            self.closed_event.clear()
            self.read_sem = threading.Semaphore(0)
            self.received_data = queue.SimpleQueue()
            self._read_thread_did_exit = False
            self._read_thread_exception = None
        self.device.close()

    def set_packet_size(self, size):
        # Custom logic for HID backend
        if size > min(self.report_in_size, self.report_out_size):
            raise DAPAccessIntf.DeviceError(
                f"DAP_Info Packet Size {size} exceeds endpoint wMaxPacketSize {min(self.report_in_size, self.report_out_size)}"
            )
        else:
            self.packet_size = size
