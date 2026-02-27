# Wouxun KG-Q10H Driver
#
# Copyright 2026 Chris Betz AF7PT
#
# Based on the work of Mel Terechenok (KG-Q10H beta driver),
# Pavel Milanes CO7WT <pavelmc@gmail.com> (KG-935G driver),
# and Krystian Struzik <toner_82@tlen.pl> who figured out the
# encryption used in Wouxun radios.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Wouxun KG-Q10H radio management module"""

import struct
import time
import logging

from chirp import util, chirp_common, bitwise, memmap, errors, directory
from chirp.drivers.wouxun_kg_common import WouxunKGBase, strxor
from chirp.settings import RadioSetting, RadioSettingGroup, \
    RadioSettingValueBoolean, RadioSettingValueList, \
    RadioSettingValueInteger, RadioSettingValueString, \
    RadioSettingValueFloat, RadioSettingValueMap, RadioSettings

LOG = logging.getLogger(__name__)

CMD_ID = 0x80
CMD_END = 0x81
CMD_WR = 0x83

MEM_VALID = 158

POWER_LEVELS = [
    chirp_common.PowerLevel("L", watts=0.5),
    chirp_common.PowerLevel("M", watts=4.5),
    chirp_common.PowerLevel("H", watts=5.5),
    chirp_common.PowerLevel("U", watts=6.0),
]

STEPS = [2.5, 5.0, 6.25, 10.0, 12.5, 25.0, 50.0, 100.0]

AIRBAND = (108000000, 136000000)

SCRAMBLER_LIST = ["Off", "1", "2", "3", "4", "5", "6", "7", "8"]
MUTE_MODE_LIST = ["Off", "QT", "QT+DTMF", "QT*DTMF"]
CALL_GROUP_LIST = [str(x) for x in range(1, 21)]

# Settings option lists
ROGER_LIST = ["OFF", "Begin", "End", "Both"]
TIMEOUT_LIST = ["OFF"] + [str(x) + "s" for x in range(15, 901, 15)]
BACKLIGHT_LIST = ["Always On"] + [str(x) + "s" for x in range(1, 21)] \
    + ["Always Off"]
PONMSG_LIST = ["Startup Display", "Battery Volts"]
DTMFST_LIST = ["OFF", "DTMF", "ANI", "DTMF+ANI"]
DTMF_TIMES = [('%dms' % t, t // 10) for t in range(50, 501, 10)]
ALERTS_LIST = ["1750 Hz", "2100 Hz", "1000 Hz", "1450 Hz"]
PTTID_LIST = ["OFF", "BOT", "EOT", "Both"]
PTTDELAY_TIMES = [('%dms' % d, d // 100) for d in range(100, 3001, 100)]
LEVEL10_LIST = ["OFF"] + [str(x) for x in range(1, 11)]
SCANGRP_LIST = ["All"] + [str(x) for x in range(1, 11)]
SCANMODE_LIST = ["TO", "CO", "SE"]
SMUTESET_LIST = ["OFF", "Rx", "Tx", "Rx+Tx"]
TONESCANSAVELIST = ["Rx", "Tx", "Tx/Rx"]
DSPBRTACT_MAP = [("%d" % x, x) for x in range(1, 11)]
DSPBRTSBY_LIST = ["OFF"] + [str(x) for x in range(1, 11)]
BATT_DISP_LIST = ["Icon", "Voltage", "Percent"]
WX_TYPE = ["Weather", "Icon-Only", "Tone", "Flash", "Tone-Flash"]
THEME_LIST = ["White-1", "White-2", "Black-1", "Black-2",
              "Cool", "Rain", "NotARubi", "Sky", "BTWR", "Candy",
              "Custom 1", "Custom 2", "Custom 3", "Custom 4"]
RPTTYPE_MAP = [("X-DIRPT", 1), ("X-TWRPT", 2)]
HOLD_TIMES = ["OFF"] + [str(x) + "s" for x in range(100, 5001, 100)]
WORKMODE_LIST = ["VFO", "Ch.Number", "Ch.Freq", "Ch.Name"]
ACTIVE_AREA_LIST = ["Area A - Top", "Area B - Bottom"]
TDR_LIST = ["TDR ON", "TDR OFF"]
PROG_KEY_LIST = ["DISABLE/UNDEF", "ALARM", "BACKLIGHT", "BRIGHT+",
                 "FAVORITE", "FLASHLIGHT", "FM-RADIO", "DISPLAY-MAP",
                 "MONITOR", "REVERSE", "SCAN", "SCAN-CTC", "SCAN-DCS",
                 "SOS", "STROBE", "TALK-AROUND", "WEATHER"]
PTT_LIST = ["Area A", "Area B", "Main Tx", "Secondary Tx",
            "Low Power", "Ultra Hi Power", "Call"]
VFO_SCANMODE_LIST = ["Current Band", "Range", "All"]

# CHIRP linear memory map (all offsets in linear space):
#   0x0000-0x02C2  Unknown / unused
#   0x02C2-0x0340  Frequency limits (RX/TX band edges)
#   0x0340-0x0440  OEM info (model, firmware, date, lock flag)
#   0x0440-0x0540  Settings (squelch, VOX, timeout, keys, display, etc.)
#   0x0540-0x05A0  VFO A (6 sub-bands, 16 bytes each)
#   0x05A0-0x05C0  VFO B (2 sub-bands, 16 bytes each)
#   0x05C0-0x05E0  Unknown
#   0x05E0-0x4460  Channel memory (1000 channels x 16 bytes)
#   0x4460-0x7340  Channel names (1000 channels x 12 bytes)
#   0x7340-0x7728  Channel valid flags (1000 bytes)
#   0x7728-0x7740  Unknown
#   0x7740-0x77E0  Scan groups (10 groups: start/end addrs + 12-char names)
#   0x77E0-0x77E8  VFO scan ranges (A + B start/end freqs)
#   0x77E8-0x78B0  Unknown
#   0x78B0-0x78E0  FM radio presets (20 x 2 bytes)
#   0x78E0-0x7B38  Call IDs (100 x 6 bytes)
#   0x7B38-0x7B40  Unknown
#   0x7B40-0x8000  Call names (100 x 12 bytes)

MEM_FORMAT = """
#seekto 0x0340;
struct {
    char    oem1[8];
    #seekto 0x036c;
    char    name[8];
    #seekto 0x0378;
    char    date[10];
    #seekto 0x0392;
    char    firmware[6];
} oem_info;

#seekto 0x0440;
struct {
    u8      channel_menu;
    u8      power_save;
    u8      roger_beep;
    u8      timeout;
    u8      toalarm;
    u8      wxalert;
    u8      wxalert_type;
    u8      vox;
    u8      unknown0448;
    u8      voice;
    u8      beep;
    u8      scan_rev;
    u8      backlight;
    u8      dsp_brt_act;
    u8      dsp_brt_sby;
    u8      ponmsg;
    u8      ptt_id;
    u8      ptt_delay;
    u8      dtmf_st;
    u8      dtmf_tx_time;
    u8      dtmf_interval;
    u8      ring_time;
    u8      alert;
    u8      autolock;
    ul16    pri_ch;
    u8      prich_sw;
    u8      rpttype;
    u8      rpt_spk;
    u8      rpt_ptt;
    u8      rpt_tone;
    u8      rpt_hold;
    u8      scan_det;
    u8      smuteset;
    u8      batt_ind;
    u8      tone_scn_save;
    #seekto 0x0464;
    u8      theme;
    u8      unknown0465;
    u8      disp_time;
    u8      time_zone;
    u8      gps_send_freq;
    u8      gps;
    u8      gps_rcv;
    ul16    custcol1_text;
    ul16    custcol1_bg;
    ul16    custcol1_icon;
    ul16    custcol1_line;
    ul16    custcol2_text;
    ul16    custcol2_bg;
    ul16    custcol2_icon;
    ul16    custcol2_line;
    ul16    custcol3_text;
    ul16    custcol3_bg;
    ul16    custcol3_icon;
    ul16    custcol3_line;
    ul16    custcol4_text;
    ul16    custcol4_bg;
    ul16    custcol4_icon;
    ul16    custcol4_line;
    char    mode_sw_pwd[6];
    char    reset_pwd[6];
    u8      work_mode_a;
    u8      work_mode_b;
    ul16    work_ch_a;
    ul16    work_ch_b;
    u8      vfostepA;
    u8      vfostepB;
    u8      squelchA;
    u8      squelchB;
    u8      bcl_a;
    u8      bcl_b;
    u8      vfoband_a;
    u8      vfoband_b;
    #seekto 0x04a7;
    u8      top_short;
    u8      top_long;
    u8      ptt1;
    u8      ptt2;
    u8      pf1_short;
    u8      pf1_long;
    u8      pf2_short;
    u8      pf2_long;
    u8      scn_grp_a_act;
    u8      scn_grp_b_act;
    u8      vfo_scanmodea;
    u8      vfo_scanmodeb;
    u8      ani_id[6];
    u8      scc[6];
    #seekto 0x04c1;
    u8      act_area;
    u8      tdr;
    u8      keylock;
    #seekto 0x04c7;
    u8      stopwatch;
    u8      unknown04c8;
    char    dispstr[12];
    #seekto 0x04dd;
    char    areamsg[12];
    u8      unknown04e9;
    u8      unknown04ea;
    u8      ani_sw;
    u8      ani_code[6];
    u8      unknown04f1;
    u8      unknown04f2;
    u8      unknown04f3;
    u8      unknown04f4;
    u8      main_band;
    u8      tdr_single_mode;
    u8      unknown04f7;
    u8      unknown04f8;
    u8      cur_call_grp;
    u8      vfo_repeater_a;
    u8      vfo_repeater_b;
    u8      sim_rec;
} settings;

#seekto 0x78B0;
struct {
    ul16    fm_radio;
} fm[20];

#seekto 0x05e0;
struct {
    ul32    rxfreq;
    ul32    txfreq;
    ul16    rxtone;
    ul16    txtone;
    u8      scrambler:4,
            am_mode:2,
            power:2;
    u8      unknown3:1,
            send_loc:1,
            scan_add:1,
            favorite:1,
            compander:1,
            mute_mode:2,
            iswide:1;
    u8      call_group;
    u8      unknown6;
} memory[1000];

#seekto 0x4460;
struct {
    u8      name[12];
} names[1000];

#seekto 0x7340;
u8 valid[1000];
"""


def _addr_rearrange(addr):
    """Swap 256-byte block order within each 1024-byte region.

    The KG-Q10H stores data with 256-byte blocks in reverse order
    within each 1024-byte region. For example, radio addresses
    0x0300, 0x0200, 0x0100, 0x0000 map to linear addresses
    0x0000, 0x0100, 0x0200, 0x0300.

    This transform is its own inverse: applying it twice returns
    the original address.
    """
    region_base = addr & 0xFC00
    block_offset = addr & 0x00FF
    block_index = (addr >> 8) & 0x03
    new_block = 3 - block_index
    return region_base | (new_block << 8) | block_offset


@directory.register
class KGQ10HRadio(WouxunKGBase):

    """Wouxun KG-Q10H"""
    VENDOR = "Wouxun"
    MODEL = "KG-Q10H"
    BAUD_RATE = 115200
    POWER_LEVELS = POWER_LEVELS
    _record_start = 0x7C
    _model = b"KG-Q10H"
    _cryptbyte = 0x54
    _download_delay = 0.005

    def process_mmap(self):
        self._memobj = bitwise.parse(MEM_FORMAT, self._mmap)

    def sync_in(self):
        try:
            self._mmap = self._download()
        except errors.RadioError:
            raise
        except Exception as e:
            raise errors.RadioError(
                "Failed to communicate with radio: %s" % e)
        self.process_mmap()

    def sync_out(self):
        try:
            self._upload()
        except errors.RadioError:
            raise
        except Exception as e:
            raise errors.RadioError(
                "Failed to communicate with radio: %s" % e)

    def _download(self):
        """Download memory from the radio and rearrange to linear order."""
        try:
            self._identify()
            raw_image = self._do_download(0, 0x8000, 64)
        except errors.RadioError:
            raise
        except Exception as e:
            LOG.exception('Unknown error during download process')
            raise errors.RadioError(
                "Failed to communicate with radio: %s" % e)

        # Rearrange from radio block order to linear CHIRP order
        raw_bytes = raw_image.get_packed()
        image = bytearray(len(raw_bytes))
        for addr in range(len(raw_bytes)):
            image[_addr_rearrange(addr)] = raw_bytes[addr]
        return memmap.MemoryMapBytes(bytes(image))

    def _upload(self):
        """Upload memory to the radio with address rearrangement."""
        try:
            self._identify()
            self._do_upload()
        except errors.RadioError:
            raise
        except Exception as e:
            raise errors.RadioError(
                "Failed to communicate with radio: %s" % e)

    def _do_upload(self):
        blocksize = 64
        for addr in range(0, 0x8000, blocksize):
            radio_addr = _addr_rearrange(addr)
            req = struct.pack('>H', radio_addr)
            chunk = self.get_mmap()[addr:addr + blocksize]
            self._write_record(CMD_WR, req + chunk)
            cserr, ack = self._read_record()
            ack_addr = struct.unpack('>H', ack)[0]
            if cserr or ack_addr != radio_addr:
                raise Exception(
                    "Radio did not ack block %i" % radio_addr)
            if self.status_fn:
                status = chirp_common.Status()
                status.cur = addr
                status.max = 0x8000
                status.msg = "Cloning to radio"
                self.status_fn(status)

        self._finish()

    # --- Serial protocol ---

    def _checksum_adjust(self, byte_val):
        """Compute the Q10H checksum adjustment.

        The Q10H applies a small offset to the checksum based on the
        4th byte (index 3) of the combined header[1:]+payload data.
        For read/write commands with a 3-byte payload, this is the
        first byte of the payload (the address high byte).
        """
        adj = (byte_val & 0x0F) % 4
        if adj == 0:
            return 3
        elif adj == 1:
            return 1
        elif adj == 2:
            return -1
        else:
            return -3

    def _write_record(self, cmd, payload=b''):
        """Build, encrypt, and send a framed record to the radio."""
        _packet = struct.pack('BBBB', self._record_start, cmd, 0xFF,
                              len(payload))
        # Checksum covers header bytes [1:] + unencrypted payload
        # Adjustment is based on byte [3] of (header[1:] + payload)
        cs_data = _packet[1:] + payload
        cs = self._checksum(cs_data)
        cs += self._checksum_adjust(cs_data[3] if len(cs_data) > 3
                                    else 0)
        checksum = bytes([cs & 0xFF])
        _packet += self.encrypt(payload + checksum)
        LOG.debug("Sent:\n%s" % util.hexprint(_packet))
        self.pipe.write(_packet)

    def _read_record(self):
        """Read and decrypt a record from the radio.

        Returns (checksum_error, decrypted_payload).
        """
        _header = self.pipe.read(4)
        if len(_header) != 4:
            raise errors.RadioError(
                'Radio did not respond')
        _length = struct.unpack('xxxB', _header)[0]
        _packet = self.pipe.read(_length)
        _rcs_xor = _packet[-1]
        _packet = self.decrypt(_packet)
        _cs = self._checksum(_header[1:])
        _cs += self._checksum(_packet)
        _cs += self._checksum_adjust(_packet[0])
        _cs &= 0xFF
        _rcs = strxor(self.pipe.read(1)[0], _rcs_xor)[0]
        return (_rcs != _cs, _packet)

    def _identify(self):
        """Send identification sequence and verify radio model.

        The Q10H CPS sends the same 8-byte read command three times
        to establish communication. The radio may respond to each one.
        We read the first response to validate, then drain any
        remaining data from the buffer. Model string is at bytes
        46-53 of the decrypted payload.
        """
        # Flush any stale data in the serial buffer
        self.pipe.reset_input_buffer()
        time.sleep(0.1)

        # Pre-encrypted read command for address 0x0000, length 3
        ident = struct.pack(
            'BBBBBBBB', 0x7c, 0x82, 0xff, 0x03,
            0x54, 0x14, 0x54, 0x53)
        for _i in range(3):
            self.pipe.write(ident)
            time.sleep(0.05)

        # Read and validate the first response
        _chksum_err, _resp = self._read_record()
        _radio_id = _resp[46:53]
        LOG.debug("Radio identified as %s" % _radio_id)
        if _chksum_err:
            raise errors.RadioError("Checksum error on identify")

        # Drain any remaining ident responses from the buffer
        time.sleep(0.1)
        self.pipe.reset_input_buffer()

        if _radio_id != self._model:
            self._finish()
            raise errors.RadioError(
                "Radio identified as %s, expected %s"
                % (_radio_id.decode('utf-8', errors='replace'),
                   self._model.decode('utf-8')))

    def _finish(self):
        """Send the finish/reboot command to end communication."""
        # Pre-encrypted finish/reboot command
        finish = struct.pack('BBBBB', 0x7c, 0x81, 0xff, 0x00, 0xd7)
        self.pipe.write(finish)

    # --- Radio features ---

    def get_features(self):
        rf = chirp_common.RadioFeatures()
        rf.has_settings = True
        rf.has_ctone = True
        rf.has_rx_dtcs = True
        rf.has_cross = True
        rf.has_tuning_step = False
        rf.has_bank = False
        rf.can_odd_split = True
        rf.valid_skips = ["", "S"]
        rf.valid_tmodes = ["", "Tone", "TSQL", "DTCS", "Cross"]
        rf.valid_cross_modes = [
            "Tone->Tone",
            "Tone->DTCS",
            "DTCS->Tone",
            "DTCS->",
            "->Tone",
            "->DTCS",
            "DTCS->DTCS",
        ]
        rf.valid_modes = ["FM", "NFM", "AM"]
        rf.valid_power_levels = self.POWER_LEVELS
        rf.valid_name_length = 12
        rf.valid_duplexes = ["", "-", "+", "split", "off"]
        rf.valid_bands = [(50000000, 54997500),
                          (108000000, 174997500),
                          (222000000, 225997500),
                          (320000000, 479997500),
                          (714000000, 999997500)]
        rf.valid_characters = chirp_common.CHARSET_ASCII
        rf.memory_bounds = (1, 999)
        rf.valid_tuning_steps = STEPS
        return rf

    @classmethod
    def get_prompts(cls):
        rp = chirp_common.RadioPrompts()
        rp.experimental = (
            'This driver is experimental. USE AT YOUR OWN RISK.\n'
            '\n'
            'Please save a copy of the image from your radio with CHIRP '
            'before modifying any values.\n'
            '\n'
            'Please keep a copy of your memories with the original Wouxun '
            'CPS software if you treasure them, as this driver is new and '
            'may contain bugs.\n'
        )
        return rp

    def get_raw_memory(self, number):
        return repr(self._memobj.memory[number])

    @classmethod
    def match_model(cls, filedata, filename):
        return False

    # --- Memory read/write ---

    def get_memory(self, number):
        _mem = self._memobj.memory[number]
        _nam = self._memobj.names[number]

        mem = chirp_common.Memory()
        mem.number = number

        _valid = self._memobj.valid[number]
        if _valid != MEM_VALID:
            mem.empty = True
            return mem

        mem.empty = False

        # frequency
        mem.freq = int(_mem.rxfreq) * 10

        # duplex and offset
        self._decode_duplex_offset(mem, _mem)

        # name (12 chars, zero-padded)
        self._decode_name(mem, _nam)

        # tones
        self._get_tone(_mem, mem)

        # skip (scan_add=1 means scan enabled, i.e. not skipped)
        mem.skip = "" if bool(_mem.scan_add) else "S"

        # power (4 levels, clamp to valid range)
        pwr = int(_mem.power) & 0x03
        mem.power = self.POWER_LEVELS[pwr]

        # mode
        if _mem.am_mode:
            mem.mode = "AM"
        elif _mem.iswide:
            mem.mode = "FM"
        else:
            mem.mode = "NFM"

        # extras
        mem.extra = RadioSettingGroup("Extra", "extra")

        rs = RadioSetting(
            "scrambler", "Scrambler",
            RadioSettingValueList(
                SCRAMBLER_LIST,
                current_index=min(int(_mem.scrambler),
                                  len(SCRAMBLER_LIST) - 1)))
        mem.extra.append(rs)

        rs = RadioSetting(
            "compander", "Compander",
            RadioSettingValueBoolean(bool(_mem.compander)))
        mem.extra.append(rs)

        rs = RadioSetting(
            "mute_mode", "Mute Mode",
            RadioSettingValueList(
                MUTE_MODE_LIST,
                current_index=min(int(_mem.mute_mode),
                                  len(MUTE_MODE_LIST) - 1)))
        mem.extra.append(rs)

        rs = RadioSetting(
            "favorite", "Favorite",
            RadioSettingValueBoolean(bool(_mem.favorite)))
        mem.extra.append(rs)

        rs = RadioSetting(
            "send_loc", "Send Location",
            RadioSettingValueBoolean(bool(_mem.send_loc)))
        mem.extra.append(rs)

        rs = RadioSetting(
            "call_group", "Call Group",
            RadioSettingValueList(
                CALL_GROUP_LIST,
                current_index=min(int(_mem.call_group),
                                  len(CALL_GROUP_LIST) - 1)))
        mem.extra.append(rs)

        return mem

    def set_memory(self, mem):
        _mem = self._memobj.memory[mem.number]
        _nam = self._memobj.names[mem.number]

        if mem.empty:
            _mem.set_raw(b"\x00" * (_mem.size() // 8))
            _nam.set_raw(b"\x00" * (_nam.size() // 8))
            self._memobj.valid[mem.number] = 0
            return

        # frequency
        _mem.rxfreq = int(mem.freq / 10)

        # duplex and offset
        if mem.duplex == "off":
            _mem.txfreq = 0xFFFFFFFF
        elif mem.duplex == "split":
            _mem.txfreq = int(mem.offset / 10)
        elif mem.duplex == "+":
            _mem.txfreq = int(mem.freq / 10) + int(mem.offset / 10)
        elif mem.duplex == "-":
            _mem.txfreq = int(mem.freq / 10) - int(mem.offset / 10)
        else:
            _mem.txfreq = int(mem.freq / 10)

        # skip (scan_add=1 means scan enabled, i.e. not skipped)
        _mem.scan_add = int(mem.skip != "S")

        # mode (AM is always wideband on this radio)
        if mem.mode == "AM":
            _mem.am_mode = 1
            _mem.iswide = 1
        elif mem.mode == "FM":
            _mem.am_mode = 0
            _mem.iswide = 1
        else:
            _mem.am_mode = 0
            _mem.iswide = 0

        # tones
        self._set_tone(mem, _mem)

        # power
        if mem.power:
            _mem.power = self.POWER_LEVELS.index(mem.power)
        else:
            _mem.power = 0

        # extras (may be absent when importing from a different radio)
        if "scrambler" in mem.extra:
            _mem.scrambler = SCRAMBLER_LIST.index(
                str(mem.extra["scrambler"].value))
        else:
            _mem.scrambler = 0

        if "compander" in mem.extra:
            _mem.compander = int(bool(mem.extra["compander"].value))
        else:
            _mem.compander = 0

        if "mute_mode" in mem.extra:
            _mem.mute_mode = MUTE_MODE_LIST.index(
                str(mem.extra["mute_mode"].value))
        else:
            _mem.mute_mode = 0

        if "favorite" in mem.extra:
            _mem.favorite = int(bool(mem.extra["favorite"].value))
        else:
            _mem.favorite = 0

        if "send_loc" in mem.extra:
            _mem.send_loc = int(bool(mem.extra["send_loc"].value))
        else:
            _mem.send_loc = 0

        if "call_group" in mem.extra:
            _mem.call_group = CALL_GROUP_LIST.index(
                str(mem.extra["call_group"].value))
        else:
            _mem.call_group = 0

        # name (12 chars, zero-padded)
        for i in range(12):
            if i < len(mem.name) and mem.name[i]:
                _nam.name[i] = ord(mem.name[i])
            else:
                _nam.name[i] = 0x0

        self._memobj.valid[mem.number] = MEM_VALID

    def validate_memory(self, mem):
        msgs = []
        if (chirp_common.in_range(mem.freq, [AIRBAND])
                and mem.mode != 'AM'):
            msgs.append(chirp_common.ValidationWarning(
                _('Frequency in this range requires AM mode')))
        if (not chirp_common.in_range(mem.freq, [AIRBAND])
                and mem.mode == 'AM'):
            msgs.append(chirp_common.ValidationWarning(
                _('Frequency in this range must not be AM mode')))
        return msgs + super().validate_memory(mem)

    # --- Settings ---

    def _get_settings(self):
        _settings = self._memobj.settings
        _oem = self._memobj.oem_info

        cfg_grp = RadioSettingGroup("cfg_grp", "Config Settings")
        key_grp = RadioSettingGroup("key_grp", "Key Settings")
        fmradio_grp = RadioSettingGroup("fmradio_grp", "FM Broadcast")
        oem_grp = RadioSettingGroup("oem_grp", "OEM Info")

        group = RadioSettings(cfg_grp, key_grp, fmradio_grp, oem_grp)

        # --- Config Settings ---

        # audio and alerts
        rs = RadioSetting("squelchA", "Squelch Level A",
                          RadioSettingValueList(
                              LEVEL10_LIST, current_index=_settings.squelchA))
        cfg_grp.append(rs)
        rs = RadioSetting("squelchB", "Squelch Level B",
                          RadioSettingValueList(
                              LEVEL10_LIST, current_index=_settings.squelchB))
        cfg_grp.append(rs)
        rs = RadioSetting("vox", "VOX Level",
                          RadioSettingValueList(
                              LEVEL10_LIST, current_index=_settings.vox))
        cfg_grp.append(rs)
        rs = RadioSetting("timeout", "Timeout Timer",
                          RadioSettingValueList(
                              TIMEOUT_LIST, current_index=_settings.timeout))
        cfg_grp.append(rs)
        rs = RadioSetting("toalarm", "Timeout Alarm",
                          RadioSettingValueList(
                              LEVEL10_LIST, current_index=_settings.toalarm))
        cfg_grp.append(rs)
        rs = RadioSetting("roger_beep", "Roger Beep",
                          RadioSettingValueList(
                              ROGER_LIST,
                              current_index=_settings.roger_beep))
        cfg_grp.append(rs)
        rs = RadioSetting("voice", "Voice Prompts",
                          RadioSettingValueBoolean(_settings.voice))
        cfg_grp.append(rs)
        rs = RadioSetting("beep", "Keypad Beep",
                          RadioSettingValueBoolean(_settings.beep))
        cfg_grp.append(rs)

        # display
        rs = RadioSetting("backlight", "Backlight Active Time",
                          RadioSettingValueList(
                              BACKLIGHT_LIST,
                              current_index=_settings.backlight))
        cfg_grp.append(rs)
        rs = RadioSetting("dsp_brt_act", "Display Brightness Active",
                          RadioSettingValueMap(
                              DSPBRTACT_MAP, _settings.dsp_brt_act))
        cfg_grp.append(rs)
        rs = RadioSetting("dsp_brt_sby", "Display Brightness Standby",
                          RadioSettingValueList(
                              DSPBRTSBY_LIST,
                              current_index=_settings.dsp_brt_sby))
        cfg_grp.append(rs)
        rs = RadioSetting("ponmsg", "Power-On Message",
                          RadioSettingValueList(
                              PONMSG_LIST,
                              current_index=_settings.ponmsg))
        cfg_grp.append(rs)

        # scan
        rs = RadioSetting("scan_rev", "Scan Mode",
                          RadioSettingValueList(
                              SCANMODE_LIST,
                              current_index=_settings.scan_rev))
        cfg_grp.append(rs)
        rs = RadioSetting("scan_det", "Scan Mode Tone Detect",
                          RadioSettingValueBoolean(_settings.scan_det))
        cfg_grp.append(rs)
        rs = RadioSetting("tone_scn_save", "Tone Scan Save",
                          RadioSettingValueList(
                              TONESCANSAVELIST,
                              current_index=_settings.tone_scn_save))
        cfg_grp.append(rs)
        rs = RadioSetting("prich_sw", "Priority Channel Scan",
                          RadioSettingValueBoolean(_settings.prich_sw))
        cfg_grp.append(rs)
        rs = RadioSetting(
            "pri_ch", "Priority Channel",
            RadioSettingValueInteger(1, 999, _settings.pri_ch))
        cfg_grp.append(rs)
        rs = RadioSetting("bcl_a", "Busy Channel Lockout A",
                          RadioSettingValueBoolean(_settings.bcl_a))
        cfg_grp.append(rs)
        rs = RadioSetting("bcl_b", "Busy Channel Lockout B",
                          RadioSettingValueBoolean(_settings.bcl_b))
        cfg_grp.append(rs)

        # DTMF
        rs = RadioSetting("dtmf_st", "DTMF Sidetone",
                          RadioSettingValueList(
                              DTMFST_LIST,
                              current_index=_settings.dtmf_st))
        cfg_grp.append(rs)
        rs = RadioSetting("dtmf_tx_time", "DTMF Tx Duration",
                          RadioSettingValueMap(
                              DTMF_TIMES, _settings.dtmf_tx_time))
        cfg_grp.append(rs)
        rs = RadioSetting("dtmf_interval", "DTMF Interval",
                          RadioSettingValueMap(
                              DTMF_TIMES, _settings.dtmf_interval))
        cfg_grp.append(rs)
        rs = RadioSetting("ptt_id", "PTT ID",
                          RadioSettingValueList(
                              PTTID_LIST,
                              current_index=_settings.ptt_id))
        cfg_grp.append(rs)
        rs = RadioSetting("ptt_delay", "PTT ID Delay",
                          RadioSettingValueMap(
                              PTTDELAY_TIMES, _settings.ptt_delay))
        cfg_grp.append(rs)
        rs = RadioSetting("alert", "Alert Tone",
                          RadioSettingValueList(
                              ALERTS_LIST,
                              current_index=_settings.alert))
        cfg_grp.append(rs)
        rs = RadioSetting("ring_time", "Ring Time",
                          RadioSettingValueList(
                              LEVEL10_LIST, current_index=_settings.ring_time))
        cfg_grp.append(rs)

        # general
        rs = RadioSetting("autolock", "Auto Key Lock",
                          RadioSettingValueBoolean(_settings.autolock))
        cfg_grp.append(rs)
        rs = RadioSetting("keylock", "Key Lock",
                          RadioSettingValueBoolean(_settings.keylock))
        cfg_grp.append(rs)
        rs = RadioSetting("stopwatch", "Stopwatch",
                          RadioSettingValueBoolean(_settings.stopwatch))
        cfg_grp.append(rs)
        rs = RadioSetting("channel_menu", "Channel Menu Mode",
                          RadioSettingValueBoolean(_settings.channel_menu))
        cfg_grp.append(rs)
        rs = RadioSetting("power_save", "Battery Saver",
                          RadioSettingValueBoolean(_settings.power_save))
        cfg_grp.append(rs)
        rs = RadioSetting("wxalert", "Weather Alert",
                          RadioSettingValueBoolean(_settings.wxalert))
        cfg_grp.append(rs)
        rs = RadioSetting("wxalert_type", "Weather Alert Type",
                          RadioSettingValueList(
                              WX_TYPE,
                              current_index=_settings.wxalert_type))
        cfg_grp.append(rs)
        rs = RadioSetting("batt_ind", "Battery Indicator",
                          RadioSettingValueList(
                              BATT_DISP_LIST,
                              current_index=_settings.batt_ind))
        cfg_grp.append(rs)
        rs = RadioSetting("theme", "Display Theme",
                          RadioSettingValueList(
                              THEME_LIST,
                              current_index=_settings.theme))
        cfg_grp.append(rs)

        # repeater
        rs = RadioSetting("rpttype", "Repeater Type",
                          RadioSettingValueMap(
                              RPTTYPE_MAP, _settings.rpttype))
        cfg_grp.append(rs)
        rs = RadioSetting("rpt_spk", "Repeater Speaker",
                          RadioSettingValueBoolean(_settings.rpt_spk))
        cfg_grp.append(rs)
        rs = RadioSetting("rpt_ptt", "Repeater PTT",
                          RadioSettingValueBoolean(_settings.rpt_ptt))
        cfg_grp.append(rs)
        rs = RadioSetting("rpt_tone", "Repeater Tone",
                          RadioSettingValueBoolean(_settings.rpt_tone))
        cfg_grp.append(rs)
        rs = RadioSetting("rpt_hold", "Repeater Hold Time",
                          RadioSettingValueList(
                              HOLD_TIMES,
                              current_index=_settings.rpt_hold))
        cfg_grp.append(rs)
        rs = RadioSetting("smuteset", "Secondary Mute",
                          RadioSettingValueList(
                              SMUTESET_LIST,
                              current_index=_settings.smuteset))
        cfg_grp.append(rs)

        # dual watch and work mode
        rs = RadioSetting("work_mode_a", "Work Mode A",
                          RadioSettingValueList(
                              WORKMODE_LIST,
                              current_index=_settings.work_mode_a))
        cfg_grp.append(rs)
        rs = RadioSetting("work_mode_b", "Work Mode B",
                          RadioSettingValueList(
                              WORKMODE_LIST,
                              current_index=_settings.work_mode_b))
        cfg_grp.append(rs)
        rs = RadioSetting(
            "work_ch_a", "Work Channel A",
            RadioSettingValueInteger(1, 999, _settings.work_ch_a))
        cfg_grp.append(rs)
        rs = RadioSetting(
            "work_ch_b", "Work Channel B",
            RadioSettingValueInteger(1, 999, _settings.work_ch_b))
        cfg_grp.append(rs)
        rs = RadioSetting("act_area", "Active Area",
                          RadioSettingValueList(
                              ACTIVE_AREA_LIST,
                              current_index=_settings.act_area))
        cfg_grp.append(rs)
        rs = RadioSetting("tdr", "TDR (Dual Watch)",
                          RadioSettingValueList(
                              TDR_LIST, current_index=_settings.tdr))
        cfg_grp.append(rs)
        rs = RadioSetting("sim_rec", "Simultaneous Receive",
                          RadioSettingValueBoolean(_settings.sim_rec))
        cfg_grp.append(rs)
        rs = RadioSetting("scn_grp_a_act", "Scan Group A Active",
                          RadioSettingValueList(
                              SCANGRP_LIST,
                              current_index=_settings.scn_grp_a_act))
        cfg_grp.append(rs)
        rs = RadioSetting("scn_grp_b_act", "Scan Group B Active",
                          RadioSettingValueList(
                              SCANGRP_LIST,
                              current_index=_settings.scn_grp_b_act))
        cfg_grp.append(rs)
        rs = RadioSetting("vfo_scanmodea", "VFO Scan Mode A",
                          RadioSettingValueList(
                              VFO_SCANMODE_LIST,
                              current_index=_settings.vfo_scanmodea))
        cfg_grp.append(rs)
        rs = RadioSetting("vfo_scanmodeb", "VFO Scan Mode B",
                          RadioSettingValueList(
                              VFO_SCANMODE_LIST,
                              current_index=_settings.vfo_scanmodeb))
        cfg_grp.append(rs)
        rs = RadioSetting("cur_call_grp", "Current Call Group",
                          RadioSettingValueList(
                              LEVEL10_LIST,
                              current_index=_settings.cur_call_grp))
        cfg_grp.append(rs)
        rs = RadioSetting("ani_sw", "ANI Switch",
                          RadioSettingValueBoolean(_settings.ani_sw))
        cfg_grp.append(rs)

        # --- Key Settings ---

        _msg = str(_settings.dispstr).split("\0")[0]
        val = RadioSettingValueString(0, 12, _msg)
        val.set_mutable(True)
        rs = RadioSetting("dispstr", "Display String", val)
        key_grp.append(rs)

        _msg = str(_settings.areamsg).split("\0")[0]
        val = RadioSettingValueString(0, 12, _msg)
        val.set_mutable(True)
        rs = RadioSetting("areamsg", "Area Message", val)
        key_grp.append(rs)

        pswdchars = "0123456789"
        _msg = str(_settings.mode_sw_pwd).split("\0")[0]
        val = RadioSettingValueString(0, 6, _msg, False)
        val.set_charset(pswdchars)
        rs = RadioSetting("mode_sw_pwd", "Mode Switch Password", val)
        key_grp.append(rs)

        _msg = str(_settings.reset_pwd).split("\0")[0]
        val = RadioSettingValueString(0, 6, _msg, False)
        val.set_charset(pswdchars)
        rs = RadioSetting("reset_pwd", "Reset Password", val)
        key_grp.append(rs)

        rs = RadioSetting("pf1_short", "PF1 Short Press",
                          RadioSettingValueList(
                              PROG_KEY_LIST,
                              current_index=_settings.pf1_short))
        key_grp.append(rs)
        rs = RadioSetting("pf1_long", "PF1 Long Press",
                          RadioSettingValueList(
                              PROG_KEY_LIST,
                              current_index=_settings.pf1_long))
        key_grp.append(rs)
        rs = RadioSetting("pf2_short", "PF2 Short Press",
                          RadioSettingValueList(
                              PROG_KEY_LIST,
                              current_index=_settings.pf2_short))
        key_grp.append(rs)
        rs = RadioSetting("pf2_long", "PF2 Long Press",
                          RadioSettingValueList(
                              PROG_KEY_LIST,
                              current_index=_settings.pf2_long))
        key_grp.append(rs)
        rs = RadioSetting("top_short", "Top Key Short Press",
                          RadioSettingValueList(
                              PROG_KEY_LIST,
                              current_index=_settings.top_short))
        key_grp.append(rs)
        rs = RadioSetting("top_long", "Top Key Long Press",
                          RadioSettingValueList(
                              PROG_KEY_LIST,
                              current_index=_settings.top_long))
        key_grp.append(rs)
        rs = RadioSetting("ptt1", "PTT1 Key",
                          RadioSettingValueList(
                              PTT_LIST, current_index=_settings.ptt1))
        key_grp.append(rs)
        rs = RadioSetting("ptt2", "PTT2 Key",
                          RadioSettingValueList(
                              PTT_LIST, current_index=_settings.ptt2))
        key_grp.append(rs)

        # --- FM Broadcast Presets ---

        for i in range(20):
            val = self._memobj.fm[i].fm_radio
            rs = RadioSetting(
                "fm[%i].fm_radio" % i, "FM Preset %i" % (i + 1),
                RadioSettingValueFloat(76.0, 108.0, val / 10.0,
                                       0.1, 1))
            fmradio_grp.append(rs)

        # --- OEM Info (read-only) ---

        def _decode(lst):
            result = ''.join([chr(int(c)) for c in lst
                              if chr(int(c)) in chirp_common.CHARSET_ASCII])
            return result

        def do_nothing(setting, obj):
            return

        _str = _decode(_oem.oem1)
        val = RadioSettingValueString(0, 8, _str)
        val.set_mutable(False)
        rs = RadioSetting("oem_info.oem1", "OEM String", val)
        rs.set_apply_callback(do_nothing, _settings)
        oem_grp.append(rs)

        _str = _decode(_oem.name)
        val = RadioSettingValueString(0, 8, _str)
        val.set_mutable(False)
        rs = RadioSetting("oem_info.name", "Model Name", val)
        rs.set_apply_callback(do_nothing, _settings)
        oem_grp.append(rs)

        _str = _decode(_oem.date)
        val = RadioSettingValueString(0, 10, _str)
        val.set_mutable(False)
        rs = RadioSetting("oem_info.date", "OEM Date", val)
        rs.set_apply_callback(do_nothing, _settings)
        oem_grp.append(rs)

        _str = _decode(_oem.firmware)
        val = RadioSettingValueString(0, 6, _str)
        val.set_mutable(False)
        rs = RadioSetting("oem_info.firmware", "Firmware Version", val)
        rs.set_apply_callback(do_nothing, _settings)
        oem_grp.append(rs)

        return group

    def get_settings(self):
        try:
            return self._get_settings()
        except Exception:
            import traceback
            LOG.error("Failed to parse settings: %s",
                      traceback.format_exc())
            return None

    def set_settings(self, settings):
        for element in settings:
            if not isinstance(element, RadioSetting):
                self.set_settings(element)
                continue
            else:
                try:
                    if "." in element.get_name():
                        bits = element.get_name().split(".")
                        obj = self._memobj
                        for bit in bits[:-1]:
                            if "[" in bit and "]" in bit:
                                bit, index = bit.split("[", 1)
                                index, _ = index.split("]", 1)
                                index = int(index)
                                obj = getattr(obj, bit)[index]
                            else:
                                obj = getattr(obj, bit)
                        setting = bits[-1]
                    else:
                        obj = self._memobj.settings
                        setting = element.get_name()

                    if element.has_apply_callback():
                        LOG.debug("Using apply callback")
                        element.run_apply_callback()
                    elif self._is_fmradio(element):
                        setattr(obj, setting,
                                int(element.values()[0]._current * 10.0))
                    else:
                        LOG.debug("Setting %s = %s" %
                                  (setting, element.value))
                        setattr(obj, setting, element.value)
                except Exception:
                    LOG.debug(element.get_name())
                    raise

    def _is_fmradio(self, element):
        return "fm_radio" in element.get_name()
