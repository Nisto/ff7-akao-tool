import os
import sys
import zlib
import struct

# http://web.archive.org/web/20180325002633/https://www41.atwiki.jp/sagafrontier/pages/43.html
# http://web.archive.org/web/20170723164454/http://wiki.qhimm.com:80/view/FF7/PSX/Sound/INSTRx.DAT

ALL_HEADER_SIZE = 16
DAT_ENTRY_SIZE = 64

def get_u16_le(buf, off=0):
    return struct.unpack("<H", buf[off:off+2])[0]

def get_u32_le(buf, off=0):
    return struct.unpack("<I", buf[off:off+4])[0]

def put_u32_le(buf, off, value):
    buf[off:off+4] = struct.pack("<I", value & 0xFFFFFFFF)

def bytes_to_samples(bytes):
    # mixed bytes -> blocks -> sample bytes
    sample_bytes = bytes // 16 * 14

    # (2 here represents scale & predictor bytes)
    if bytes % 16 > 2:
        # + residual sample bytes
        sample_bytes += bytes % 16 - 2

    # -> samples (nibbles)
    return sample_bytes * 2

def get_samples(datbuf, allbuf):
    samples = { }

    base_spu_addr = get_u32_le(allbuf, 0x00)

    datoff = 0

    sample = 0

    while datoff < len(datbuf):

        spu_addr = get_u32_le(datbuf, datoff)

        if spu_addr >= base_spu_addr:

            sample_offset = ALL_HEADER_SIZE + (spu_addr - base_spu_addr)

            if datoff+DAT_ENTRY_SIZE < len(datbuf) and get_u32_le(datbuf, datoff+DAT_ENTRY_SIZE) >= base_spu_addr:
                sample_size = get_u32_le(datbuf, datoff+DAT_ENTRY_SIZE) - spu_addr
            else:
                sample_size = len(allbuf) - sample_offset

            header = bytearray(4096)

            header[0x00:0x04] = b"GENH"

            sample_rate = get_u32_le(datbuf, datoff+0x10) * 44100 // 4096 # pitch (pt) -> frequency (Hz)

            loop_start = bytes_to_samples( get_u32_le(datbuf, datoff+0x04) - spu_addr )
            loop_end = bytes_to_samples( sample_size )

            put_u32_le(header, 0x04, 1)            # channels
            put_u32_le(header, 0x08, 0)            # interleave
            put_u32_le(header, 0x0C, 22050)        # sample rate
            put_u32_le(header, 0x10, loop_start)   # loop start
            put_u32_le(header, 0x14, loop_end)     # loop end
            put_u32_le(header, 0x18, 0)            # coding = PSX
            put_u32_le(header, 0x1C, 4096)         # audio start offset
            put_u32_le(header, 0x20, 4096)         # size of this header
            put_u32_le(header, 0x40, loop_end)     # num samples
            put_u32_le(header, 0x50, sample_size)  # data size

            samples[sample] = header + allbuf[sample_offset:sample_offset+sample_size]

            sample += 1

        datoff += DAT_ENTRY_SIZE

    return samples

notes = [ "C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B", "Tie", "Rest" ]

durations = [ 192, 36, 48, 24, 12, 6, 3, 32, 18, 8, 4 ]

commands = {
    0xA0: [1, "sequence end"],
    0xA1: [2, "set voice number"], # set voice number (corresponds to sample number in INSTR.* files)
    0xA2: [2, "set note length (forced)"],
    0xA3: [2, "set volume"],
    0xA4: [3, "set pitch"],
    0xA5: [2, "set octave"],
    0xA6: [1, "set octave + 1"],
    0xA7: [1, "set octave - 1"],
    0xA8: [2, "set expression"],
    0xA9: [3, "set expression (slide)"],
    0xAA: [2, "set panpot"],
    0xAB: [3, "set panpot (slide)"],
    0xAD: [2, "unknown"],
    0xAE: [2, "unknown"],
    0xAF: [2, "unknown"],
    0xB1: [2, "unknown"],
    0xB2: [2, "unknown"],
    0xB3: [1, "restore hardware envelope"],
    0xB4: [4, "delay"],
    0xB5: [2, "pitch LFO amplitude"],
    0xB6: [1, "disable pitch LFO"],
    0xB7: [2, "unknown"],
    0xB8: [4, "set volume LFO"],
    0xB9: [2, "set amplitude of volume LFO"], # disable volume LFO
    0xBA: [1, "end volume LFO"],
    0xBB: [2, "unknown"],
    0xBC: [3, "set panpot LFO"],
    0xBD: [2, "set amplitude of panpot LFO"],
    0xC0: [2, "trance"],
    0xC2: [1, "Reverb On"],
    0xC3: [1, "Reverb Off"],
    0xC6: [1, "FM Modulation On"],
    0xC7: [1, "FM Modulation Off"],
    0xC8: [1, "Repeat Start"],
    0xC9: [2, "repeat end (w/ repeat count)"], # Repeat End (w/ repeat count)
    0xCA: [1, "repeat end"], # Repeat End (repeat twice)
    0xCC: [1, "Slur On"],
    0xCD: [1, "Slur Off"],
    0xD0: [1, "unknown"],
    0xD1: [1, "unknown"],
    0xD3: [2, "unknown"],
    0xD8: [2, "pitch bend"], # pitch bend (in 8th notes?)
    0xDB: [1, "unknown"],
    0xDD: [3, "Pitch Bend LFO"],
    0xDE: [3, "Volume LFO"],
    0xE5: [1, "unknown"],
    0xE8: [3, "set tempo"],
    0xE9: [4, "tempo glide"],
    0xEA: [3, "set reverb depth"],
    0xEC: [3, "percussion start"],
    0xED: [1, "percussion end"],
    0xEE: [3, "goto"], # goto (signed 16-bit word address, relative to the address after the parameter value)
    0xF0: [4, "goto maybe"], # goto maybe (conditional goto)
    0xF1: [4, "unknown"],
    0xF2: [2, "set voice number (only apply attack rate)"],
    0xF4: [2, "unknown"],
    0xF5: [1, "unknown"],
    0xF6: [2, "unknown"],
    0xF7: [2, "unknown"],
    0xF8: [2, "unknown"],
    0xF9: [2, "unknown"],
    0xFA: [1, "unknown"],
    0xFB: [1, "unknown"],
    0xFD: [3, "set timebase + time"],
    0xFE: [3, "measure"],
    0xFF: [1, "unknown"],
}

class AKAO:

    def __init__(self, buf, log=False):
        self.buf = buf
        self.log = log

        self.id = struct.unpack("<H", self.buf[0x04:0x06])[0]
        self.size = struct.unpack("<H", self.buf[0x06:0x08])[0]
        self.chmask = struct.unpack("<I", self.buf[0x10:0x14])[0]

        self.tracks = 0

        for i in range(32):
            if self.chmask & (1 << i):
                self.tracks += 1

        if self.tracks > 0:

            self.trk_size_tbl = []

            self.trk_off_tbl = []

            for i in range(self.tracks):

                offset = 0x14 + i * 2
                offset += 2 + struct.unpack("<H", self.buf[offset:offset+2])[0]

                if i + 1 < self.tracks:
                    next_offset = 0x14 + (i + 1) * 2
                    next_offset += 2 + struct.unpack("<H", self.buf[next_offset:next_offset+2])[0]
                    size = next_offset - offset
                else:
                    size = len(self.buf) - offset

                self.trk_size_tbl.append(size)

                self.trk_off_tbl.append(offset)

        self.set_track(0)

    def set_track(self, trknum):
        self.trknum        = trknum
        self.trk_size      = self.trk_size_tbl[self.trknum]
        self.trk_off_start = self.trk_off_tbl[self.trknum]
        self.trk_off_end   = self.trk_off_start + self.trk_size
        self.offset        = self.trk_off_start

        if self.log:
            print("\n")
            print("Track %02d" % self.trknum)
            print("================================================================================")

    def step(self):
        bytecode = self.buf[self.offset]

        if self.log:
            print("0x%X: " % self.offset, end="")

        if bytecode <= 0x99: # note/sustain/rest
            oplen = 1
            note = notes[bytecode // 11]
            ticks = durations[bytecode % 11]

            if self.log:
                print("note = %s" % note, end="; ")
                print("duration = %d ticks" % ticks)
        elif bytecode in commands: # command
            oplen, dsc = commands[bytecode]

            if self.log:
                print("command = %s" % dsc, end="")

                if oplen > 1:
                    print("; param bytes = ", end="")

                if oplen >= 2:
                    print("0x%02X" % self.buf[self.offset+1], end=" ")
                if oplen >= 3:
                    print("0x%02X" % self.buf[self.offset+2], end=" ")
                if oplen >= 4:
                    print("0x%02X" % self.buf[self.offset+3], end=" ")

                print(end="\n")
        else:
            sys.exit("Unknown bytecode at 0x%X: 0x%02X" % (self.offset, bytecode))

        self.offset += oplen

def main(argc=len(sys.argv), argv=sys.argv):
    if argc < 3 or argv[1].lower() not in ['s', 'd', 'p']:
        print("Usage:")
        print()
        print("* Dump isolated tracks:")
        print("  akao-tool s [-l] <file|dir>")
        print()
        print("* Dump used samples:")
        print("  akao-tool d [-l] <file|dir> <instr-dir> <out-dir>")
        print()
        print("* Dump event data (parse only):")
        print("  akao-tool p [-l] <file|dir>")
        print()
        print("<file> can be an AKAO file or a PSF file")
        print()
        print("Specify -l to enable logging human-readable event data")
        return 1

    mode = argv[1].lower()

    log = argv[2].lower() == '-l'

    path = os.path.realpath(argv[3] if log else argv[2])

    if mode == 'd':
        if (not log and argc < 4) or (log and argc < 5):
            print("Specify path to *.INSTR directory!")
            return 1

        if (not log and argc < 5) or (log and argc < 6):
            print("Specify an output directory for the samples!")
            return 1

        instr_dir = argv[4] if log else argv[3]

        out_dir = argv[5] if log else argv[4]

        dat1path = os.path.join(instr_dir, r"INSTR.DAT")
        if not os.path.isfile(dat1path):
            print("Could not find INSTR.DAT!")
            return 1

        all1path = os.path.join(instr_dir, r"INSTR.ALL")
        if not os.path.isfile(all1path):
            print("Could not find INSTR.ALL!")
            return 1

        dat2path = os.path.join(instr_dir, r"INSTR2.DAT")
        if not os.path.isfile(dat2path):
            print("Could not find INSTR2.DAT!")
            return 1

        all2path = os.path.join(instr_dir, r"INSTR2.ALL")
        if not os.path.isfile(all2path):
            print("Could not find INSTR2.ALL!")
            return 1

        with open(dat1path, "rb") as dat1: dat1buf = dat1.read()
        with open(all1path, "rb") as all1: all1buf = all1.read()
        with open(dat2path, "rb") as dat2: dat2buf = dat2.read()
        with open(all2path, "rb") as all2: all2buf = all2.read()

        instr_samples = get_samples(dat1buf, all1buf)
        instr2_samples = get_samples(dat2buf, all2buf)

        out_dir = os.path.realpath(out_dir)

        if not os.path.isdir(out_dir):
            os.makedirs(out_dir)

    if os.path.isdir(path):
        filepaths = [os.path.join(path, filename) for filename in os.listdir(path)]
    else:
        filepaths = [path]

    for filepath in filepaths:

        stem, ext = os.path.splitext(filepath)

        title = os.path.basename(stem)

        is_psf = False

        with open(filepath, "rb") as file:

            magic = file.read(4)

            file.seek(0)

            if magic == b"AKAO":
                akao_buf = file.read()
            elif magic == b"PSF\x01":
                is_psf = True

                psf_header = file.read(16)

                if len(psf_header) != 16:
                    print("Could not read PSF header! :: %s" % filepath)
                    return 1

                zlib_size = struct.unpack("<I", psf_header[0x08:0x0C])[0]

                zlib_buf = file.read(zlib_size)

                psf_tags = file.read()

                exe_buf = bytearray( zlib.decompress(zlib_buf) )

                akao_off = exe_buf.find(b"AKAO")

                if akao_off == -1:
                    print("Could not find AKAO data in PSF! :: %s" % filepath)
                    return 1

                akao_header = exe_buf[akao_off:akao_off+16]

                akao_size = 16 + struct.unpack("<H", akao_header[0x06:0x08])[0]

                akao_buf = exe_buf[akao_off:akao_off+akao_size]
            else:
                print("Unrecognized container in file! :: %s" % filepath)
                return 1

        if mode == 's':
            # to avoid redundant logging, set logging to False at first
            akao = AKAO(akao_buf, False)

            for trkout in range(akao.tracks):

                akao_out_buf = bytearray(akao.buf)

                # turn logging back on if requested
                if trkout == akao.tracks - 1:
                    akao.log = log

                for trknum in range(akao.tracks):

                    akao.set_track(trknum)

                    while akao.offset < akao.trk_off_end:

                        bytecode = akao.buf[akao.offset]

                        if bytecode == 0xA3 or bytecode == 0xA8:

                            if trknum != trkout:

                                akao_out_buf[akao.offset+1] = 0

                        akao.step()

                if is_psf:
                    exe_buf[akao_off:akao_off+akao_size] = akao_out_buf
                    zlib_buf = zlib.compress(exe_buf)
                    out_buf = b"PSF\x01"
                    out_buf += (b"\x00" * 0x04)
                    out_buf += struct.pack("<I", len(zlib_buf))
                    out_buf += struct.pack("<I", zlib.crc32(zlib_buf) & 0xFFFFFFFF)
                    out_buf += zlib_buf
                    out_buf += psf_tags
                else:
                    out_buf = akao_out_buf

                out_path = "%s (track %02d)%s" % (stem, trkout, ext)

                with open(out_path, "wb") as outfile:

                    outfile.write(out_buf)

            # for trknum in range(akao.tracks):
            # 
            #     akao.set_track(trknum)
            # 
            #     # start with original 16-byte header
            #     new_akao_buf = bytearray(akao_header)
            # 
            #     # channel mask (count = 1)
            #     new_akao_buf += b"\x01\x00\x00\x00"
            # 
            #     # relative offset of data for ch 0
            #     new_akao_buf += b"\x00\x00"
            # 
            #     # append track data
            #     new_akao_buf += akao.buf[akao.trk_start_off:akao.trk_end_off]
            # 
            #     # new AKAO size
            #     new_akao_size = len(new_akao_buf) - len(header)
            # 
            #     # update the file size in the header
            #     new_akao_buf[0x06:0x08] = struct.pack("<H", new_akao_size)
            # 
            #     # filename, e.g.: Wutai (track 04).minipsf
            #     out_path = "%s (track %02d)%s" % (stem, trknum, ext)
            #
            #     D'OH! this won't work, we always need the tempo, time signature, etc. from track 0
        elif mode == 'p':
            akao = AKAO(akao_buf, log)

            for trknum in range(akao.tracks):

                akao.set_track(trknum)

                while akao.offset < akao.trk_off_end:

                    # bytecode = akao.buf[akao.offset]
                    # 
                    # if bytecode in commands:
                    #     oplen, dsc = commands[bytecode]
                    #     if dsc == "unknown":
                    # 
                    #         print("unknown op @ 0x%X" % akao.offset, end="")
                    # 
                    #         if oplen > 1:
                    #             print("; value = ", end="")
                    # 
                    #         if oplen >= 2:
                    #             print("0x%02X", akao.buf[akao.offset+1], end=" ")
                    #         if oplen >= 3:
                    #             print("0x%02X", akao.buf[akao.offset+2], end=" ")
                    #         if oplen >= 4:
                    #             print("0x%02X", akao.buf[akao.offset+3], end=" ")
                    # 
                    #         print(end="\n")

                    akao.step()
        elif mode == 'd':
            akao = AKAO(akao_buf, log)

            used_instr = []

            for trknum in range(akao.tracks):

                akao.set_track(trknum)

                while akao.offset < akao.trk_off_end:

                    bytecode = akao.buf[akao.offset]

                    if bytecode == 0xA1 or bytecode == 0xF2:

                        instr_num = akao.buf[akao.offset+1]

                        if instr_num not in used_instr:

                            used_instr.append(instr_num)

                    akao.step()

            for sample in used_instr:
            
                genhdir = os.path.join(out_dir, title)
            
                if not os.path.isdir(genhdir):
                    os.mkdir(genhdir)
            
                genhpath = os.path.join(genhdir, "%02X.genh" % sample)
            
                with open(genhpath, "wb") as genh:
                    if akao.id == 0x52 and sample >= 0x35: # One-Winged Angel vocal samples
                        genh.write(instr2_samples[sample - 0x35])
                    else:
                        genh.write(instr_samples[sample])

if __name__ == "__main__":
    main()