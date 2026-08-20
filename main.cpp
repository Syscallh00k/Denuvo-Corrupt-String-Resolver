#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <fstream>
#include <sstream>

struct Section { std::string name; uint32_t va, vsize, rawptr, rawsize; };
class PeImage {
public:
    std::vector<uint8_t> buf;
    uint64_t imageBase = 0;
    uint32_t sizeOfImage = 0;
    std::vector<Section> secs;

    template<class T> T rd(size_t off) const {
        T v{}; if (off + sizeof(T) <= buf.size()) std::memcpy(&v, &buf[off], sizeof(T)); return v;
    }
    bool load(const char* path) {
        FILE* f = fopen(path, "rb");
        if (!f) { fprintf(stderr, "Couldn't open %s -- is the path right?\n", path); return false; }
        fseek(f, 0, SEEK_END); size_t n = (size_t)ftell(f); fseek(f, 0, SEEK_SET);
        buf.resize(n); fread(buf.data(), 1, n, f); fclose(f);
        if (buf.size() < 0x40 || buf[0] != 'M' || buf[1] != 'Z') return false;
        uint32_t pe = rd<uint32_t>(0x3C);
        if (pe + 0x100 > buf.size() || std::memcmp(&buf[pe], "PE\0\0", 4)) return false;
        uint16_t nsec = rd<uint16_t>(pe + 6), optsz = rd<uint16_t>(pe + 20);
        size_t opt = pe + 24;
        if (rd<uint16_t>(opt) != 0x20B) return false;
        imageBase = rd<uint64_t>(opt + 24);
        sizeOfImage = rd<uint32_t>(opt + 56);
        size_t st = opt + optsz;
        for (int i = 0; i < nsec; i++) {
            size_t o = st + (size_t)i * 40; Section s; char nm[9] = {};
            std::memcpy(nm, &buf[o], 8); s.name = nm;
            s.vsize = rd<uint32_t>(o + 8); s.va = rd<uint32_t>(o + 12);
            s.rawsize = rd<uint32_t>(o + 16); s.rawptr = rd<uint32_t>(o + 20);
            secs.push_back(s);
        }
        return true;
    }
    int64_t rva2off(uint32_t rva) const {
        for (auto& s : secs) {
            uint32_t span = std::max(s.vsize, s.rawsize);
            if (rva >= s.va && rva < s.va + span) {
                uint32_t d = rva - s.va; if (d >= s.rawsize) return -1;
                return (int64_t)s.rawptr + d;
            }
        }
        return -1;
    }
    const Section* secOf(uint32_t rva) const {
        for (auto& s : secs) { uint32_t sp = std::max(s.vsize, s.rawsize); if (rva >= s.va && rva < s.va + sp) return &s; }
        return nullptr;
    }
    bool va2rva(uint64_t va, uint32_t& out) const {
        if (va < imageBase) return false; uint64_t r = va - imageBase;
        if (r >= sizeOfImage) return false; out = (uint32_t)r; return true;
    }
    template<class T> bool readRVA(uint32_t rva, T& out) const {
        int64_t o = rva2off(rva); if (o < 0 || (size_t)o + sizeof(T) > buf.size()) return false;
        std::memcpy(&out, &buf[o], sizeof(T)); return true;
    }
    std::string cstr(uint32_t rva, size_t maxlen = 256) const {
        int64_t o = rva2off(rva); if (o < 0) return {};
        std::string s;
        for (size_t i = 0; i < maxlen && (size_t)o + i < buf.size(); i++) {
            char c = (char)buf[o + i];
            if (!c) return s;
            unsigned char uc = (unsigned char)c;
            if (uc < 0x20 || uc > 0x7E) return {};
            s.push_back(c);
        }
        return {};
    }
    std::string wcstr(uint32_t rva, size_t maxchars = 128) const {
        int64_t o = rva2off(rva); if (o < 0) return {};
        std::string s;
        for (size_t i = 0; i < maxchars; i++) {
            size_t off2 = (size_t)o + i * 2;
            if (off2 + 1 >= buf.size()) break;
            uint16_t wc; std::memcpy(&wc, &buf[off2], 2); if (!wc) break;
            if (wc < 0x80) s.push_back((char)wc);
            else s += '?';
        }
        return s;
    }
};

struct InsnInfo {
    int length;
    bool isRet;
    bool isCall;
    bool isJmp;
    bool isCJmp;
    bool isRipRel;
    int32_t ripDisp;
    int   ripOff;
    int32_t relDisp;
    int   relOff;
    bool isBad;
};

static InsnInfo decodeInsnFull(const uint8_t* b, size_t avail) {
    InsnInfo I = {};
    if (avail == 0) { I.length = 1; I.isBad = true; return I; }

    size_t o = 0; int rex = 0; bool opsz = false, f3 = false, f2 = false, f0 = false;
    for (;o < avail; o++) {
        uint8_t p = b[o];
        if (p == 0xF3) f3 = true;
        else if (p == 0xF2) f2 = true;
        else if (p == 0x66) opsz = true;
        else if (p == 0xF0) f0 = true;
        else if (p == 0x2E || p == 0x36 || p == 0x3E || p == 0x26 || p == 0x64 || p == 0x65 || p == 0x67) {}
        else break;
    }
    if (o < avail && b[o] >= 0x40 && b[o] <= 0x4F) rex = b[o++];
    if (o >= avail) { I.length = (int)o; I.isBad = true; return I; }

    uint8_t op = b[o++]; bool two = false; uint8_t op2 = 0;
    if (op == 0x0F) { if (o >= avail) { I.length=(int)o; I.isBad=true; return I; } two = true; op2 = b[o++]; }

    auto skipModrm = [&](bool hasSib, bool hasDisp8, bool hasDisp32, bool hasImm8, bool hasImm32) -> bool {
        if (o >= avail) return false;
        uint8_t modrm = b[o++]; int mod = modrm >> 6, rm = modrm & 7;
        if (!two && mod == 0 && rm == 5 && !hasSib) {
            if (o + 4 > avail) return false;
            int32_t disp; std::memcpy(&disp, b + o, 4);
            I.isRipRel = true;
            I.ripDisp = disp;
            I.ripOff = (int)o;
            o += 4;
        } else {
            bool needSib = (rm == 4 && mod != 3);
            if (needSib) { if (o >= avail) return false; uint8_t sib = b[o++]; if (mod == 0 && (sib & 7) == 5) { if (o + 4 > avail) return false; o += 4; } }
            if (mod == 1) { if (o >= avail) return false; o++; }
            else if (mod == 2) { if (o + 4 > avail) return false; o += 4; }
        }
        if (hasImm8) { if (o >= avail) return false; o++; }
        if (hasImm32) { if (o + 4 > avail) return false; o += 4; }
        return true;
    };

    auto noModrm = [&](int immBytes) -> bool {
        if (immBytes > 0 && (size_t)(o + immBytes) > avail) return false;
        o += immBytes; return true;
    };

    bool ok = true;
    if (!two) {
        switch (op) {
        case 0xC3: I.isRet = true; break;
        case 0xCB: I.isRet = true; break;
        case 0xC2: case 0xCA: I.isRet = true; ok = noModrm(2); break;
        case 0xE8:
            if (o + 4 > avail) { ok = false; break; }
            std::memcpy(&I.relDisp, b + o, 4); I.relOff = (int)o;
            I.isCall = true; o += 4; break;
        case 0xE9:
            if (o + 4 > avail) { ok = false; break; }
            std::memcpy(&I.relDisp, b + o, 4); I.relOff = (int)o;
            I.isJmp = true; o += 4; break;
        case 0xEB:
            if (o >= avail) { ok = false; break; }
            I.relDisp = (int8_t)b[o]; I.relOff = (int)o;
            I.isJmp = true; o++; break;
        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75:
        case 0x76: case 0x77: case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F:
            if (o >= avail) { ok = false; break; }
            I.isCJmp = true; o++; break;
        case 0x88: case 0x8A: ok = skipModrm(false,false,false,false,false); break;
        case 0x89: case 0x8B: ok = skipModrm(false,false,false,false,false); break;
        case 0x8D: ok = skipModrm(false,false,false,false,false); break;
        case 0xC7: ok = skipModrm(false,false,false,false,!opsz); break;
        case 0xC6: ok = skipModrm(false,false,false,true,false); break;
        case 0x00: case 0x01: case 0x02: case 0x03:
        case 0x08: case 0x09: case 0x0A: case 0x0B:
        case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x18: case 0x19: case 0x1A: case 0x1B:
        case 0x20: case 0x21: case 0x22: case 0x23:
        case 0x28: case 0x29: case 0x2A: case 0x2B:
        case 0x30: case 0x31: case 0x32: case 0x33:
        case 0x38: case 0x39: case 0x3A: case 0x3B:
        case 0x84: case 0x85: case 0x86: case 0x87:
            ok = skipModrm(false,false,false,false,false); break;
        case 0x80: ok = skipModrm(false,false,false,true,false); break;
        case 0x81: ok = skipModrm(false,false,false,false,!opsz); break;
        case 0x83: ok = skipModrm(false,false,false,true,false); break;
        case 0xFF: case 0xFE: ok = skipModrm(false,false,false,false,false); break;
        case 0xF6: ok = skipModrm(false,false,false, (b[o-1]>>3&7)==0||((b[o-1]>>3)&7)==1, false); break;
        case 0xF7: ok = skipModrm(false,false,false,false, (b[o-1]>>3&7)==0||((b[o-1]>>3)&7)==1); break;
        case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: break;
        case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F: break;
        case 0x68: ok = noModrm(opsz ? 2 : 4); break;
        case 0x6A: ok = noModrm(1); break;
        case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5: case 0xB6: case 0xB7:
            ok = noModrm(1); break;
        case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            ok = noModrm((rex & 8) ? 8 : (opsz ? 2 : 4)); break;
        case 0x90: case 0x98: case 0x99: case 0xC9: case 0xCC: case 0xF4: break;
        case 0x63: ok = skipModrm(false,false,false,false,false); break;
        case 0xD0: case 0xD1: case 0xD2: case 0xD3: ok = skipModrm(false,false,false,false,false); break;
        case 0xC1: ok = skipModrm(false,false,false,true,false); break;
        case 0xA0: case 0xA1: case 0xA2: case 0xA3: ok = noModrm((rex&8)?8:(opsz?2:4)); break;
        case 0xA4: case 0xA5: case 0xA6: case 0xA7: break;
        case 0xAA: case 0xAB: case 0xAC: case 0xAD: break;
        case 0xA8: ok = noModrm(1); break;
        case 0xA9: ok = noModrm(opsz?2:4); break;
        case 0x3C: ok = noModrm(1); break;
        case 0x3D: ok = noModrm(opsz?2:4); break;
        case 0x69: ok = skipModrm(false,false,false,false,!opsz); break;
        case 0x6B: ok = skipModrm(false,false,false,true,false); break;
        case 0xAE: case 0xAF: break;
        case 0xCD: ok = noModrm(1); break;
        case 0xC8: ok = noModrm(3); break;
        case 0x8F: ok = skipModrm(false,false,false,false,false); break;
        default:
            I.isBad = true; break;
        }
    } else {
        switch (op2) {
        case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85:
        case 0x86: case 0x87: case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8C: case 0x8D: case 0x8E: case 0x8F:
            if (o + 4 > avail) { ok = false; break; }
            I.isCJmp = true; o += 4; break;
        case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95:
        case 0x96: case 0x97: case 0x98: case 0x99: case 0x9A: case 0x9B:
        case 0x9C: case 0x9D: case 0x9E: case 0x9F:
            ok = skipModrm(false,false,false,false,false); break;
        case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45:
        case 0x46: case 0x47: case 0x48: case 0x49: case 0x4A: case 0x4B:
        case 0x4C: case 0x4D: case 0x4E: case 0x4F:
            ok = skipModrm(false,false,false,false,false); break;
        case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: case 0x15:
        case 0x16: case 0x17: case 0x28: case 0x29: case 0x2A: case 0x2B:
        case 0x2C: case 0x2D: case 0x2E: case 0x2F:
        case 0x51: case 0x54: case 0x55: case 0x56: case 0x57: case 0x58:
        case 0x59: case 0x5A: case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        case 0x6E: case 0x6F: case 0x7E: case 0x7F:
        case 0xD6: case 0xEF:
        case 0xB6: case 0xB7: case 0xBE: case 0xBF:
        case 0xAF: case 0x1F:
        case 0x5B: case 0x53: case 0x64:
            ok = skipModrm(false,false,false,false,false); break;
        case 0xC6: ok = skipModrm(false,false,false,true,false); break;
        case 0xBC: case 0xBD: ok = skipModrm(false,false,false,false,false); break;
        case 0xC8: case 0xC9: case 0xCA: case 0xCB: case 0xCC: case 0xCD: case 0xCE: case 0xCF:
            break;
        case 0xC0: case 0xC1: ok = skipModrm(false,false,false,false,false); break;
        case 0xB0: case 0xB1: ok = skipModrm(false,false,false,false,false); break;
        case 0xA3: case 0xAB: case 0xBA: ok = skipModrm(false,false,false,false,false); break;
        case 0x31: break;
        case 0xA0: break;
        case 0xA8: break;
        case 0x05: break;
        default:
            I.isBad = true; break;
        }
    }
    if (!ok) { I.length = (int)o; I.isBad = true; return I; }
    I.length = (int)o;
    return I;
}

static bool isPrologue(const uint8_t* b, size_t avail) {
    if (avail < 2) return false;
    if (b[0] == 0x48 && b[1] == 0x89 && avail >= 4) {
        uint8_t r = b[2] & 0x38;
        if (b[3] == 0x24 && (r == 0x18 || r == 0x28 || r == 0x30 || r == 0x38)) return true;
    }
    if (b[0] == 0x48 && b[1] == 0x83 && b[2] == 0xEC) return true;
    if (b[0] == 0x40 && (b[1] == 0x53 || b[1] == 0x55 || b[1] == 0x56 || b[1] == 0x57)) return true;
    if (b[0] == 0x41 && b[1] >= 0x54 && b[1] <= 0x57) return true;
    if (b[0] == 0x48 && b[1] == 0x8B && b[2] == 0xC4) return true;
    if (b[0] == 0x55 && avail >= 2 && (b[1] == 0x48 || b[1] == 0x57 || b[1] == 0x56)) return true;
    if (b[0] == 0x53 && avail >= 2 && (b[1] == 0x48 || b[1] == 0x41 || b[1] == 0x56)) return true;
    if ((b[0] == 0x56 || b[0] == 0x57) && avail >= 2 && (b[1] == 0x48 || b[1] == 0x41)) return true;
    if (b[0] == 0x4C && b[1] == 0x89 && avail >= 4 && b[3] == 0x24) return true;
    return false;
}

struct StringRef { uint32_t instrRva; uint32_t targetRva; std::string str; };

struct FuncInfo {
    uint32_t startRva;
    uint32_t size;
    std::vector<uint32_t> calls;
    std::vector<StringRef> strRefs;
    int badInsns;
    bool complete;
};

static FuncInfo walkFunction(const PeImage& pe, const Section& text,
                              uint32_t startRva, uint32_t maxSize = 0x8000)
{
    FuncInfo fi; fi.startRva = startRva; fi.size = 0; fi.badInsns = 0; fi.complete = false;
    const Section* rdata = nullptr;
    for (auto& s : pe.secs) if (s.name == ".rdata") { rdata = &s; break; }

    int64_t textOff = pe.rva2off(startRva);
    if (textOff < 0) return fi;
    const uint8_t* base = pe.buf.data() + textOff;
    size_t avail = std::min((size_t)(text.va + text.rawsize - startRva), (size_t)maxSize);
    if (avail == 0) return fi;

    size_t o = 0;
    while (o < avail) {
        size_t rem = avail - o;
        InsnInfo ins = decodeInsnFull(base + o, rem);
        if (ins.length <= 0) { fi.badInsns++; o++; continue; }
        if (ins.isBad) fi.badInsns++;

        uint32_t instrRva = startRva + (uint32_t)o;

        if (ins.isRipRel && rdata) {
            uint32_t nextRva = instrRva + (uint32_t)ins.length;
            int64_t targetRaw = (int64_t)nextRva + ins.ripDisp;
            if (targetRaw >= rdata->va && targetRaw < (int64_t)(rdata->va + rdata->vsize)) {
                uint32_t tgt = (uint32_t)targetRaw;
                std::string s = pe.cstr(tgt, 128);
                if (s.empty()) s = pe.wcstr(tgt, 64);
                if (!s.empty()) {
                    fi.strRefs.push_back({ instrRva, tgt, s });
                }
            }
        }

        if (ins.isCall) {
            uint32_t nextRva = instrRva + (uint32_t)ins.length;
            uint32_t tgt = (uint32_t)((int64_t)nextRva + ins.relDisp);
            const Section* ts = pe.secOf(tgt);
            if (ts && ts->name == ".text") fi.calls.push_back(tgt);
        }

        if (ins.isRet) { o += (size_t)ins.length; fi.complete = true; break; }

        if (ins.isJmp) {
            uint32_t nextRva = instrRva + (uint32_t)ins.length;
            int64_t dst = (int64_t)nextRva + ins.relDisp;
            o += (size_t)ins.length;
            if (dst < (int64_t)startRva || dst > (int64_t)(startRva + maxSize)) {
                fi.complete = true; break;
            }
            continue;
        }

        o += (size_t)ins.length;
        if (fi.badInsns > 20 && o < 64) { fi.size = (uint32_t)o; return fi; }
    }
    fi.size = (uint32_t)o;
    return fi;
}

static std::vector<uint32_t> findFunctionStarts(const PeImage& pe, const Section& text) {
    std::vector<uint32_t> starts;
    const uint8_t* tb = pe.buf.data() + text.rawptr;
    size_t n = std::min(text.rawsize, (uint32_t)(pe.buf.size() - text.rawptr));

    for (size_t i = 0; i < n; i++) {
        if (i >= 2) {
            bool afterPad = false;
            if (tb[i - 1] == 0xCC && tb[i - 2] == 0xCC) afterPad = true;
            if (tb[i - 1] == 0x90 && tb[i - 2] == 0x90) afterPad = true;
            if (tb[i - 1] == 0xCC) afterPad = true;
            if (tb[i - 1] == 0x00 && tb[i - 2] == 0x00) afterPad = true;

            if (afterPad && isPrologue(tb + i, n - i)) {
                starts.push_back(text.va + (uint32_t)i);
            }
        }
        if ((i & 0xF) == 0 && isPrologue(tb + i, n - i)) {
            uint32_t rva = text.va + (uint32_t)i;
            if (starts.empty() || starts.back() != rva)
                starts.push_back(rva);
        }
    }
    std::sort(starts.begin(), starts.end());
    starts.erase(std::unique(starts.begin(), starts.end()), starts.end());
    return starts;
}

struct KnownFunc { uint32_t rva; const char* name; const char* desc; };
static const KnownFunc kKnownFuncs[] = {
    {0x002ED2FA, "Legend__CL_Frame",                        "per-frame client update, signon state machine"},
    {0x002E992E, "Legend__CL_CopyNewEntity",                "instantiate newly-networked entity from baseline"},
    {0x00259AA0, "Legend__CL_RecvTable_Decode",             "decode entity delta against RecvTable decoder"},
    {0x00250C60, "Legend__RecvTable_BuildDecoder",          "build flattened prop decoder"},
    {0x00250960, "Legend__RecvTable_Flatten",               "recursively flatten nested sub-tables"},
    {0x0025A120, "Legend__RecvTable_MergeDeltas",           "apply decoded property deltas to entity"},
    {0x00300B00, "Legend__CClientState_AdvanceFrameTime",   "advance tickcount/frametime/curtime"},
    {0x00BD5DD0, "Legend__CPlayer_GetCameraOrigin",         "camera_origin @ +0x1FD4, gated by +0x41BA"},
    {0x004AE490, "Legend__FS_LoadScriptFile",               "filesystem read/route for .nut/.gnut scripts"},
    {0x00B3C4F0, "Legend__ScriptVM_RegisterClientGlobals",  "bulk-register natives/constants into client VM"},
};

static std::string formatBytes(const uint8_t* b, int len) {
    std::string s;
    for (int i = 0; i < len && i < 10; i++) {
        char tmp[4]; snprintf(tmp, sizeof tmp, "%02X ", b[i]); s += tmp;
    }
    while ((int)s.size() < 32) s += ' ';
    return s;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Apex Legends .text function reconstructor\n");
        printf("usage: %s <dump.exe> [-o outdir]\n\n", argv[0]);
        printf("It writes out two files:\n");
        printf("  ida_defines.py       IDAPython script -- undefines the dq blobs, makes functions, names them\n");
        printf("  recovered_funcs.txt  a readable disassembly dump with the strings it found\n");
        return 1;
    }
    const char* inpath = argv[1];
    std::string outdir = ".";
    for (int i = 2; i < argc; i++) if (!strcmp(argv[i], "-o") && i + 1 < argc) outdir = argv[++i];

    PeImage pe;
    if (!pe.load(inpath)) return 2;
    printf("Loaded %s  (base 0x%llX, %u bytes, %zu sections)\n",
        inpath, (unsigned long long)pe.imageBase, pe.sizeOfImage, pe.secs.size());

    const Section* text = nullptr;
    for (auto& s : pe.secs) if (s.name == ".text") { text = &s; break; }
    if (!text) { fprintf(stderr, "No .text section in there -- can't do anything without it.\n"); return 3; }
    printf("Found .text at RVA 0x%X  (file offset 0x%X, 0x%X bytes)\n", text->va, text->rawptr, text->rawsize);

    printf("Scanning .text for function prologues -- give it a few seconds...\n");
    fflush(stdout);
    std::vector<uint32_t> starts = findFunctionStarts(pe, *text);
    printf("Got %zu candidate starts.\n", starts.size());

    for (auto& kf : kKnownFuncs) {
        bool found = std::binary_search(starts.begin(), starts.end(), kf.rva);
        if (!found) starts.push_back(kf.rva);
    }
    std::sort(starts.begin(), starts.end());
    starts.erase(std::unique(starts.begin(), starts.end()), starts.end());

    printf("Walking all %zu of them now...\n", starts.size());
    std::vector<FuncInfo> funcs;
    funcs.reserve(starts.size());
    size_t complete_count = 0;
    for (uint32_t rva : starts) {
        FuncInfo fi = walkFunction(pe, *text, rva);
        if (fi.size < 4) continue;
        if (fi.badInsns > (int)(fi.size / 2)) continue;
        funcs.push_back(fi);
        if (fi.complete) complete_count++;
    }
    printf("Kept %zu of them, %zu ran clean to a RET.\n", funcs.size(), complete_count);

    std::map<uint32_t, std::pair<std::string, std::string>> knownMap;
    for (auto& kf : kKnownFuncs) knownMap[kf.rva] = { kf.name, kf.desc };

    size_t totalStrRefs = 0;
    for (auto& fi : funcs) totalStrRefs += fi.strRefs.size();
    printf("Resolved %zu string references along the way.\n", totalStrRefs);

    std::string pypath = outdir + "/ida_defines.py";
    {
        std::ofstream o(pypath);
        o << "import idc, idaapi, ida_funcs, ida_bytes, ida_auto, ida_name\n\n";
        o << "IMAGE_BASE = 0x" << std::hex << pe.imageBase << std::dec << "\n";
        o << "def ea(rva): return IMAGE_BASE + rva\n\n";

        o << "def undefine_region(start_rva, size):\n";
        o << "    a = ea(start_rva)\n";
        o << "    ida_bytes.del_items(a, ida_bytes.DELIT_SIMPLE, max(size, 16))\n\n";
        o << "regions = [\n";
        for (auto& fi : funcs)
            o << "    (0x" << std::hex << fi.startRva << ", 0x" << fi.size << std::dec << "),\n";
        o << "]\n";
        o << "for rva, sz in regions:\n";
        o << "    undefine_region(rva, sz)\n";
        o << "print(f'Cleared {len(regions)} regions.')\n\n";

        o << "created = 0; failed = 0\n";
        o << "for rva, sz in regions:\n";
        o << "    a = ea(rva)\n";
        o << "    if ida_funcs.add_func(a):\n";
        o << "        created += 1\n";
        o << "    else:\n";
        o << "        cur = a\n";
        o << "        for _ in range(min(sz, 512)):\n";
        o << "            l = idc.create_insn(cur)\n";
        o << "            if l <= 0: break\n";
        o << "            cur += l\n";
        o << "        if ida_funcs.add_func(a): created += 1\n";
        o << "        else: failed += 1\n";
        o << "print(f'Made {created} functions ({failed} wouldn\\'t take).')\n\n";

        o << "names = [\n";
        for (auto& kf : kKnownFuncs)
            o << "    (0x" << std::hex << kf.rva << std::dec
              << ", '" << kf.name << "', '" << kf.desc << "'),\n";
        o << "]\n";
        o << "for rva, name, desc in names:\n";
        o << "    a = ea(rva)\n";
        o << "    idc.set_name(a, name, idc.SN_CHECK | idc.SN_NOCHECK)\n";
        o << "    idc.set_func_cmt(a, desc, 0)\n";
        o << "print(f'Renamed the {len(names)} functions we already know.')\n\n";

        o << "import re\n";
        o << "str_refs = [\n";
        size_t refCount = 0;
        for (auto& fi : funcs) {
            for (auto& sr : fi.strRefs) {
                std::string esc;
                for (char c : sr.str) {
                    unsigned char uc = (unsigned char)c;
                    if (c == '\'')       esc += "\\'";
                    else if (c == '\\')  esc += "\\\\";
                    else if (c == '\n')  esc += "\\n";
                    else if (c == '\t')  esc += "\\t";
                    else if (uc < 0x20 || uc > 0x7E) {
                        char tmp[8]; snprintf(tmp, sizeof tmp, "\\x%02x", uc); esc += tmp;
                    }
                    else esc.push_back(c);
                }
                if (esc.size() > 80) esc = esc.substr(0, 77) + "...";
                o << "    (0x" << std::hex << sr.instrRva << ", 0x" << sr.targetRva << std::dec
                  << ", '" << esc << "'),\n";
                refCount++;
                if (refCount > 50000) { o << "    # (cut off here -- too many to list)\n"; goto done_refs; }
            }
        }
        done_refs:
        o << "]\n";
        o << "for rva, tgt_rva, s in str_refs:\n";
        o << "    idc.set_cmt(ea(rva), f'-> \"{s}\"  [RVA 0x{tgt_rva:X}]', 0)\n";
        o << "print(f'Dropped {len(str_refs)} string comments in.')\n\n";

        o << "ida_auto.auto_wait()\n";
        o << "print('All done -- go check the .text window.')\n";
    }
    printf("Wrote %s\n", pypath.c_str());

    std::string txtpath = outdir + "/recovered_funcs.txt";
    {
        std::ofstream o(txtpath);
        o << "apex_definer recovered function listing\n";
        char hb[128]; snprintf(hb, sizeof hb, "source: %s  base=0x%llX\n\n",
            inpath, (unsigned long long)pe.imageBase);
        o << hb;
        o << "functions: " << funcs.size() << "  string_refs: " << totalStrRefs << "\n";
        o << "==========================================================================\n\n";

        for (auto& fi : funcs) {
            auto kit = knownMap.find(fi.startRva);
            char hdr[200];
            if (kit != knownMap.end())
                snprintf(hdr, sizeof hdr, "[%s]  RVA 0x%08X  size=0x%X  %s\n",
                    kit->second.first.c_str(), fi.startRva, fi.size, fi.complete?"[RET]":"[?]");
            else
                snprintf(hdr, sizeof hdr, "[sub_0x%08X]  RVA 0x%08X  size=0x%X  %s\n",
                    fi.startRva, fi.startRva, fi.size, fi.complete?"[RET]":"[?]");
            o << hdr;

            int64_t textOff = pe.rva2off(fi.startRva);
            if (textOff >= 0) {
                const uint8_t* base = pe.buf.data() + textOff;
                size_t avail = std::min((size_t)fi.size, (size_t)(pe.buf.size() - textOff));
                size_t off = 0;
                while (off < avail) {
                    InsnInfo ins = decodeInsnFull(base + off, avail - off);
                    if (ins.length <= 0) { off++; continue; }
                    uint32_t instrRva = fi.startRva + (uint32_t)off;
                    char line[160];
                    snprintf(line, sizeof line, "  0x%08X  %s",
                        instrRva, formatBytes(base + off, ins.length).c_str());
                    o << line;
                    for (auto& sr : fi.strRefs) {
                        if (sr.instrRva == instrRva) {
                            std::string trunc = sr.str;
                            if (trunc.size() > 60) trunc = trunc.substr(0, 57) + "...";
                            o << "  ; -> \"" << trunc << "\"";
                        }
                    }
                    if (ins.isCall) {
                        uint32_t tgt = (uint32_t)((int64_t)(instrRva + ins.length) + ins.relDisp);
                        auto tkit = knownMap.find(tgt);
                        if (tkit != knownMap.end())
                            o << "  ; CALL " << tkit->second.first;
                        else {
                            char tmp[32]; snprintf(tmp, sizeof tmp, "  ; CALL 0x%X", tgt);
                            o << tmp;
                        }
                    }
                    o << "\n";
                    if (ins.isRet) break;
                    off += (size_t)ins.length;
                }
            }

            if (!fi.strRefs.empty()) {
                o << "  -- strings referenced --\n";
                std::set<std::string> seen;
                for (auto& sr : fi.strRefs) {
                    if (seen.count(sr.str)) continue; seen.insert(sr.str);
                    std::string t = sr.str;
                    if (t.size() > 80) t = t.substr(0, 77) + "...";
                    char tmp[200]; snprintf(tmp, sizeof tmp, "    [0x%08X -> 0x%08X] \"%s\"\n",
                        sr.instrRva, sr.targetRva, t.c_str());
                    o << tmp;
                }
            }
            o << "\n";
        }

        o << "\n==========================================================================\n";
        o << "STRING REFERENCE INDEX\n";
        o << "==========================================================================\n\n";
        std::map<std::string, std::vector<uint32_t>> strIndex;
        for (auto& fi : funcs)
            for (auto& sr : fi.strRefs)
                strIndex[sr.str].push_back(fi.startRva);
        for (auto& [str, rvas] : strIndex) {
            std::string t = str; if (t.size() > 60) t = t.substr(0, 57) + "...";
            o << "\"" << t << "\"\n";
            for (uint32_t rva : rvas) {
                auto kit = knownMap.find(rva);
                if (kit != knownMap.end())
                    o << "    referenced in: " << kit->second.first << " (0x" << std::hex << rva << std::dec << ")\n";
                else
                    o << "    referenced in: sub_0x" << std::hex << rva << std::dec << "\n";
            }
        }
    }
    printf("Wrote %s\n", txtpath.c_str());
    printf("Done. Load ida_defines.py in IDA and it'll define everything and drop the string comments in.\n");
    return 0;
}
