#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdarg>
#include <cmath>
#include <cstring>
#include <cctype>
#include <vector>
#include <string>
#include <algorithm>
#include <map>
#include <cstdlib>
#include <ctime>

#include "InternalsPlugin.hpp"

#pragma comment(lib, "user32.lib")

static const char *PLUGIN_NAME = "rf2_puppeteer";
static const char *PLUGIN_VERSION_STR = "0.1";

// RVAs from rf2_ai_strength.py (IDA base 0x140000000)
static const unsigned long long ADDR_MODE_INDEX    = 0x13B99A0ULL;
static const unsigned long long STRENGTH_SLOTS[5]  = { 0x13B91F8ULL, 0x13B9230ULL, 0x13B9268ULL, 0x13B92A0ULL, 0x13B92D8ULL };
static const unsigned long long ADDR_AGGRESSION    = 0x13B9150ULL;
static const unsigned long long ADDR_VALUE_COUNT   = 0x1342D90ULL;
static const unsigned long long ADDR_PTR_ARRAY     = 0x1342DA0ULL;
static const unsigned long long ADDR_INLINE_COUNT  = 0x1342D94ULL;
static const unsigned long long ADDR_INLINE_ARRAY  = 0x197DB10ULL;
static const unsigned long long INLINE_STRIDE      = 0xE2D8ULL;

static const unsigned long long ADDR_CALIB_E8 = 0x139EFE8ULL;
static const unsigned long long ADDR_CALIB_EC = 0x139EFECULL;
static const unsigned long long ADDR_CALIB_F0 = 0x139EFF0ULL;
static const unsigned long long ADDR_CALIB_D0 = 0x139EFD0ULL;

static const unsigned long long F_STRENGTH_FACTOR = 0xDA5CULL;
static const unsigned long long F_RANDOM_PRODUCT  = 0xDA38ULL;
static const unsigned long long F_TARGET_FACTOR   = 0xDA44ULL;
static const unsigned long long F_CURRENT_FACTOR  = 0xDB18ULL;
static const unsigned long long F_EXTRA_FACTOR    = 0xDB1CULL;
static const unsigned long long F_AGGRESSION      = 0xDA60ULL;
static const unsigned long long F_LIMITER         = 0xDA64ULL;
static const unsigned long long F_LIMITER_APPLIED = 0xDA40ULL;

static const unsigned long long NAME_TABLE_BASE   = 0xDDC0ULL;
static const unsigned long long NAME_INDEX_OFFSET = 0xDE84ULL;
static const unsigned long long NAME_ENTRY_SIZE   = 0x40ULL;
static const int MAX_NAME_INDEX = 15;

static const int MIN_STRENGTH = 10;
static const int MAX_STRENGTH = 120;
static const int MAX_BOTS = 64;

#if defined(DEBUG) || defined(_DEBUG)
static CRITICAL_SECTION gLogCs;
static bool gLogCsInit = false;
static FILE *gLogFile = NULL;
static bool gLogDisabled = false;

static void LogInit()
{
    if (gLogDisabled) return;
    if (!gLogCsInit) {
        InitializeCriticalSection(&gLogCs);
        gLogCsInit = true;
    }
    EnterCriticalSection(&gLogCs);
    if (!gLogFile && !gLogDisabled) {
        DWORD attr = GetFileAttributesA("C:\\test\\");
        if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
            gLogDisabled = true;
        } else {
            gLogFile = fopen("C:\\test\\rf2_puppeteer.log", "a");
            if (!gLogFile) gLogDisabled = true;
        }
    }
    LeaveCriticalSection(&gLogCs);
}

static void Log(const char *fmt, ...)
{
    if (gLogDisabled) return;
    if (!gLogCsInit) LogInit();
    if (gLogDisabled || !gLogFile) return;
    EnterCriticalSection(&gLogCs);
    if (gLogFile) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(gLogFile, "[%04d-%02d-%02d %02d:%02d:%02d.%03d] ",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        va_list ap;
        va_start(ap, fmt);
        vfprintf(gLogFile, fmt, ap);
        va_end(ap);
        fprintf(gLogFile, "\n");
        fflush(gLogFile);
    }
    LeaveCriticalSection(&gLogCs);
}
#else
#define LogInit() ((void)0)
#define Log(...) ((void)0)
#endif

static bool IsFiniteD(double x)
{
    return _finite(x) != 0;
}

static double ClampD(double x, double lo, double hi)
{
    if (x < lo) return lo;
    if (x > hi) return hi;
    return x;
}

static int ClampI(int x, int lo, int hi)
{
    if (x < lo) return lo;
    if (x > hi) return hi;
    return x;
}

static unsigned char *Base()
{
    return (unsigned char *)GetModuleHandleA(NULL);
}

static bool ReadMem(const void *addr, void *out, size_t size)
{
    __try {
        memcpy(out, addr, size);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool WriteMem(void *addr, const void *in, size_t size)
{
    DWORD oldProt = 0;
    BOOL okProt = VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &oldProt);
    __try {
        memcpy(addr, in, size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (okProt) {
            DWORD tmp = 0;
            VirtualProtect(addr, size, oldProt, &tmp);
        }
        return false;
    }
    if (okProt) {
        DWORD tmp = 0;
        VirtualProtect(addr, size, oldProt, &tmp);
    }
    return true;
}

static bool ReadU32(unsigned long long rva, unsigned int &out)
{
    return ReadMem(Base() + rva, &out, sizeof(out));
}

static bool ReadI32(unsigned long long rva, int &out)
{
    return ReadMem(Base() + rva, &out, sizeof(out));
}

static bool ReadF32(unsigned long long rva, float &out)
{
    return ReadMem(Base() + rva, &out, sizeof(out));
}

static bool ReadU64(unsigned long long rva, unsigned long long &out)
{
    return ReadMem(Base() + rva, &out, sizeof(out));
}

static bool WriteI32(unsigned long long rva, int val)
{
    return WriteMem(Base() + rva, &val, sizeof(val));
}

static bool WriteF32(unsigned long long rva, float val)
{
    return WriteMem(Base() + rva, &val, sizeof(val));
}

static bool ReadObjU64(unsigned long long obj, unsigned long long off, unsigned long long &out)
{
    return ReadMem((void *)(uintptr_t)(obj + off), &out, sizeof(out));
}

static bool ReadObjI32(unsigned long long obj, unsigned long long off, int &out)
{
    return ReadMem((void *)(uintptr_t)(obj + off), &out, sizeof(out));
}

static bool ReadObjF32(unsigned long long obj, unsigned long long off, float &out)
{
    return ReadMem((void *)(uintptr_t)(obj + off), &out, sizeof(out));
}

static bool WriteObjF32(unsigned long long obj, unsigned long long off, float val)
{
    return WriteMem((void *)(uintptr_t)(obj + off), &val, sizeof(val));
}

static bool ReadObjBytes(unsigned long long obj, unsigned long long off, void *out, size_t size)
{
    return ReadMem((void *)(uintptr_t)(obj + off), out, size);
}

static bool WriteObjBytes(unsigned long long obj, unsigned long long off, const void *in, size_t size)
{
    return WriteMem((void *)(uintptr_t)(obj + off), in, size);
}


static bool ValidObject(unsigned long long ptr)
{
    return ptr >= 0x10000ULL && ptr <= 0x7FFFFFFFFFFFULL && ((ptr & 7ULL) == 0ULL);
}

static std::string Trim(const std::string &s)
{
    size_t a = 0;
    while (a < s.size() && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    size_t b = s.size();
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

static bool PlausibleName(const std::string &s)
{
    if (s.empty()) return false;
    if (s.find("\\") != std::string::npos) return false;
    if (s.find("/") != std::string::npos) return false;
    if (s.find(":") != std::string::npos) return false;
    if (s.find(".INI") != std::string::npos) return false;
    if (s.find(".JSON") != std::string::npos) return false;
    if (s.find(".HDV") != std::string::npos) return false;
    if (s.find(".VEH") != std::string::npos) return false;
    bool allDigits = true;
    for (size_t i = 0; i < s.size(); ++i) {
        if (!isdigit((unsigned char)s[i])) { allDigits = false; break; }
    }
    if (allDigits) return false;
    int words = 0;
    bool inWord = false;
    for (size_t i = 0; i < s.size(); ++i) {
        if (isspace((unsigned char)s[i])) { inWord = false; }
        else if (!inWord) { inWord = true; ++words; }
    }
    if (words > 6) return false;
    return true;
}

static std::string StripNameSuffix(const std::string &s)
{
    // remove previously appended " 120,36" or " 120" or " [STR=...]" / " [AGGR=...]" style
    std::string out = s;
    // remove [STR=...] or [AGGR=...]
    size_t p = out.rfind(" [STR=");
    if (p != std::string::npos && out.size() > p && out[out.size() - 1] == ']') out = out.substr(0, p);
    p = out.rfind(" [AGGR=");
    if (p != std::string::npos && out.size() > p && out[out.size() - 1] == ']') out = out.substr(0, p);

    // remove trailing " <num>,<num>" or " <num>"
    while (true) {
        std::string t = Trim(out);
        size_t sp = t.rfind(' ');
        if (sp == std::string::npos) break;
        std::string tail = t.substr(sp + 1);
        bool ok = !tail.empty();
        bool hasComma = false;
        for (size_t i = 0; i < tail.size(); ++i) {
            char c = tail[i];
            if (c == ',') { if (hasComma) { ok = false; break; } hasComma = true; }
            else if (c == '-' || c == '+') { if (i != 0) { ok = false; break; } }
            else if (!isdigit((unsigned char)c)) { ok = false; break; }
        }
        // only strip if it looks like our appended number/aggr form
        if (ok && hasComma) {
            out = t.substr(0, sp);
            continue;
        }
        // also strip plain trailing number if it was our old form? be careful - only strip "digits" or "digits,digits"
        if (ok && !hasComma) {
            // strip only if all digits (old format)
            bool allD = true;
            for (size_t i = 0; i < tail.size(); ++i) if (!isdigit((unsigned char)tail[i])) allD = false;
            if (allD) { out = t.substr(0, sp); continue; }
        }
        break;
    }
    return Trim(out);
}

static std::string ShortDriverName(const std::string &name)
{
    std::string base = StripNameSuffix(Trim(name));
    size_t sp = base.find_first_of(" \t");
    if (sp == std::string::npos) return base;
    return base.substr(0, sp);
}

static bool ReadNameEntry(unsigned long long addr, std::string &outText, std::vector<unsigned char> &outRaw)
{
    unsigned char raw[NAME_ENTRY_SIZE];
    if (!ReadMem((void *)(uintptr_t)addr, raw, NAME_ENTRY_SIZE)) return false;
    int end = NAME_ENTRY_SIZE;
    for (int i = 0; i < (int)NAME_ENTRY_SIZE; ++i) {
        if (raw[i] == 0) { end = i; break; }
    }
    std::string s;
    for (int i = 0; i < end; ++i) {
        unsigned char c = raw[i];
        if (c < 32 || c > 126) return false;
        s.push_back((char)c);
    }
    s = Trim(s);
    if (s.size() < 2 || s.size() > NAME_ENTRY_SIZE - 1) return false;
    if (!PlausibleName(s)) return false;
    outText = s;
    outRaw.assign(raw, raw + NAME_ENTRY_SIZE);
    return true;
}

static bool ReadDriverName(unsigned long long obj, const std::string &fallback, std::string &outName, int &outIndex, std::vector<unsigned char> &outRaw)
{
    outName = fallback;
    outIndex = -1;
    outRaw.clear();
    int idx = -1;
    if (!ReadObjI32(obj, NAME_INDEX_OFFSET, idx)) return false;
    if (idx < 0 || idx > MAX_NAME_INDEX) return false;
    unsigned long long addr = obj + NAME_TABLE_BASE + NAME_ENTRY_SIZE * (unsigned long long)idx;
    std::string text;
    std::vector<unsigned char> raw;
    if (!ReadNameEntry(addr, text, raw)) return false;
    outName = text;
    outIndex = idx;
    outRaw = raw;
    return true;
}

static std::string MakePatchedName(const std::string &rawName, int strength, int aggr)
{
    std::string base = ShortDriverName(rawName);
    if (base.empty()) base = "AI";
    char tail[64];
    _snprintf(tail, sizeof(tail), " %d,%d", strength, aggr);
    tail[sizeof(tail) - 1] = '\0';
    std::string out = base + tail;
    if (out.size() >= NAME_ENTRY_SIZE) {
        size_t maxBase = (NAME_ENTRY_SIZE - 1) - strlen(tail);
        if (maxBase < 1) maxBase = 1;
        if (base.size() > maxBase) base = base.substr(0, maxBase);
        out = base + tail;
    }
    if (out.size() >= NAME_ENTRY_SIZE) out = out.substr(0, NAME_ENTRY_SIZE - 1);
    return out;
}

static bool WriteName(unsigned long long obj, int nameIndex, const std::string &rawName, int strength, int aggr)
{
    if (nameIndex < 0 || nameIndex > MAX_NAME_INDEX) return false;
    std::string name = MakePatchedName(rawName, strength, aggr);
    unsigned char buf[NAME_ENTRY_SIZE];
    memset(buf, 0, sizeof(buf));
    size_t n = name.size();
    if (n >= NAME_ENTRY_SIZE) n = NAME_ENTRY_SIZE - 1;
    memcpy(buf, name.c_str(), n);
    unsigned long long addr = obj + NAME_TABLE_BASE + NAME_ENTRY_SIZE * (unsigned long long)nameIndex;
    if (!WriteObjBytes(obj, NAME_TABLE_BASE + NAME_ENTRY_SIZE * (unsigned long long)nameIndex, buf, NAME_ENTRY_SIZE)) return false;
    unsigned char check[NAME_ENTRY_SIZE];
    if (!ReadObjBytes(obj, NAME_TABLE_BASE + NAME_ENTRY_SIZE * (unsigned long long)nameIndex, check, NAME_ENTRY_SIZE)) return false;
    return memcmp(check, buf, NAME_ENTRY_SIZE) == 0;
}


static bool ParseRange(const char *text, int &outMin, int &outMax, int loLimit, int hiLimit)
{
    if (!text) return false;
    std::string s = Trim(text);
    if (s.empty()) return false;
    // accept "90-100" or "120-95" (reverse) or "90,100" or "90 100"
    for (size_t i = 0; i < s.size(); ++i) if (s[i] == ',') s[i] = '-';
    int a = 0, b = 0;
    char extra = 0;
    if (sscanf(s.c_str(), "%d-%d%c", &a, &b, &extra) == 2) {
        if (a < loLimit || a > hiLimit || b < loLimit || b > hiLimit) return false;
        outMin = a; outMax = b;
        return true;
    }
    if (sscanf(s.c_str(), "%d%c", &a, &extra) == 1) {
        if (a < loLimit || a > hiLimit) return false;
        outMin = a; outMax = a;
        return true;
    }
    return false;
}

static double FactorForStrength(int strength, double e8, double ec, double f0)
{
    double s = (double)strength;
    if (s < 70.0) return (s / 70.0) * e8;
    if (s <= 100.0) {
        double t = (s - 70.0) / 30.0;
        return (1.0 - t) * e8 + t * ec;
    }
    double t = (s - 100.0) / 20.0;
    return (1.0 - t) * ec + t * f0;
}

static int StrengthForFactor(double factor, double e8, double ec, double f0)
{
    if (!IsFiniteD(factor) || !IsFiniteD(e8) || !IsFiniteD(ec) || !IsFiniteD(f0)) return -1;
    if (!(e8 > 0.0 && e8 < ec && ec < f0)) return -1;
    double s;
    if (factor <= e8) s = 70.0 * factor / e8;
    else if (factor <= ec) s = 70.0 + 30.0 * (factor - e8) / (ec - e8);
    else s = 100.0 + 20.0 * (factor - ec) / (f0 - ec);
    if (!IsFiniteD(s)) return -1;
    int v = (int)floor(s + 0.5);
    return ClampI(v, MIN_STRENGTH, MAX_STRENGTH);
}

struct AiObject {
    unsigned long long obj;
    std::string label;
    std::string name;
    std::string baseName;
    int nameIndex;
    std::vector<unsigned char> nameRaw;
};

static void CollectAiObjects(std::vector<AiObject> &out)
{
    out.clear();
    std::vector<std::pair<unsigned long long, std::string> > targets;

    unsigned int nPtr = 0;
    if (ReadU32(ADDR_VALUE_COUNT, nPtr) && nPtr <= (unsigned int)MAX_BOTS) {
        for (unsigned int i = 0; i < nPtr; ++i) {
            if (i == 0) continue;
            unsigned long long obj = 0;
            unsigned long long rva = ADDR_PTR_ARRAY + (unsigned long long)i * 8ULL;
            if (ReadU64(rva, obj) && ValidObject(obj)) {
                char lbl[32];
                _snprintf(lbl, sizeof(lbl), "ptr[%u]", i);
                lbl[sizeof(lbl) - 1] = '\0';
                targets.push_back(std::make_pair(obj, std::string(lbl)));
            }
        }
    }

    unsigned int nInline = 0;
    if (ReadU32(ADDR_INLINE_COUNT, nInline) && nInline <= (unsigned int)MAX_BOTS) {
        for (unsigned int i = 0; i < nInline; ++i) {
            if (i == 0) continue;
            unsigned long long obj = (unsigned long long)(uintptr_t)(Base() + ADDR_INLINE_ARRAY + (unsigned long long)i * INLINE_STRIDE);
            char lbl[32];
            _snprintf(lbl, sizeof(lbl), "inline[%u]", i);
            lbl[sizeof(lbl) - 1] = '\0';
            targets.push_back(std::make_pair(obj, std::string(lbl)));
        }
    }

    std::vector<unsigned long long> seen;
    for (size_t i = 0; i < targets.size(); ++i) {
        bool dup = false;
        for (size_t j = 0; j < seen.size(); ++j) if (seen[j] == targets[i].first) { dup = true; break; }
        if (dup) continue;
        seen.push_back(targets[i].first);

        unsigned long long obj = targets[i].first;
        float fStrength = 0.0f;
        if (!ReadObjF32(obj, F_STRENGTH_FACTOR, fStrength)) continue;
        if (!IsFiniteD(fStrength) || !(fStrength > 0.0f && fStrength <= 2.0f)) continue;

        AiObject ai;
        ai.obj = obj;
        ai.label = targets[i].second;
        ai.nameIndex = -1;
        std::string nm;
        int idx = -1;
        std::vector<unsigned char> raw;
        if (ReadDriverName(obj, ai.label, nm, idx, raw)) {
            ai.name = nm;
            ai.nameIndex = idx;
            ai.nameRaw = raw;
        } else {
            ai.name = ai.label;
        }
        ai.baseName = ShortDriverName(ai.name);
        if (ai.baseName.empty()) ai.baseName = ai.name;
        out.push_back(ai);
    }
}

static std::string LowerAscii(const std::string &s)
{
    std::string o = s;
    for (size_t i = 0; i < o.size(); ++i) o[i] = (char)tolower((unsigned char)o[i]);
    return o;
}

static bool MatchName(const std::string &a, const std::string &b)
{
    std::string aa = LowerAscii(ShortDriverName(a));
    std::string bb = LowerAscii(ShortDriverName(b));
    if (aa.empty() || bb.empty()) return false;
    if (aa == bb) return true;
    // also try full stripped lower compare
    std::string fa = LowerAscii(Trim(StripNameSuffix(a)));
    std::string fb = LowerAscii(Trim(StripNameSuffix(b)));
    if (!fa.empty() && fa == fb) return true;
    return false;
}

struct ScoringOrder {
    std::string name;
    int place; // 1-based, lower is better
    bool isPlayer;
};

static int FindScoringPlace(const std::vector<ScoringOrder> &order, const AiObject &ai, bool useSlotOrder, int slotIndex)
{
    if (useSlotOrder) return slotIndex + 1;
    for (size_t i = 0; i < order.size(); ++i) {
        if (order[i].isPlayer) continue;
        if (MatchName(order[i].name, ai.name) || MatchName(order[i].name, ai.baseName)) {
            return order[i].place > 0 ? order[i].place : (int)i + 1;
        }
    }
    // fallback: slot order
    return slotIndex + 1;
}


static const char *VAR_STRENGTH_FIRST = "StrengthFirst";
static const char *VAR_STRENGTH_LAST  = "StrengthLast";
static const char *VAR_AGGR_FIRST     = "AggrFirst";
static const char *VAR_AGGR_LAST      = "AggrLast";
static const char *VAR_REVENGE          = "Revenge";
static const char *VAR_REVENGE_STRENGTH = "RevengeStrength";
static const char *VAR_REVENGE_AGGR     = "RevengeAggr";
static const char *VAR_REVENGE_COOLDOWN = "RevengeCooldown";
static const char *VAR_REVENGE_BOTS     = "RevengeBots";

static const int DEFAULT_STRENGTH_FIRST  = 95;
static const int DEFAULT_STRENGTH_LAST   = 120;
static const int DEFAULT_AGGR_FIRST      = 20;
static const int DEFAULT_AGGR_LAST       = 40;
static const int DEFAULT_REVENGE         = 120;
static const int DEFAULT_REVENGE_STRENGTH = 120;
static const int DEFAULT_REVENGE_AGGR     = 120;
static const int DEFAULT_REVENGE_COOLDOWN = 60;
static const int DEFAULT_REVENGE_BOTS     = 5;

class Rf2PuppeteerPlugin : public InternalsPluginV07
{
public:
    Rf2PuppeteerPlugin()
    {
        mStrengthFirst = DEFAULT_STRENGTH_FIRST;
        mStrengthLast  = DEFAULT_STRENGTH_LAST;
        mAggrFirst     = DEFAULT_AGGR_FIRST;
        mAggrLast      = DEFAULT_AGGR_LAST;
        mRevenge         = DEFAULT_REVENGE;
        mRevengeStrength = DEFAULT_REVENGE_STRENGTH;
        mRevengeAggr     = DEFAULT_REVENGE_AGGR;
        mRevengeCooldownSec = DEFAULT_REVENGE_COOLDOWN;
        mRevengeBots     = DEFAULT_REVENGE_BOTS;
        mApplyPending = false;
        mAppliedSession = -9999;
        mSessionStartET = -1000000.0;
        mLastSession = -9999;
        mScoringValid = false;
        memset(&mLastScoring, 0, sizeof(mLastScoring));
        mLastScoringVehicles.clear();
        mPrevLapDist.clear();
        mLastRevengeCheckET = -1000.0;
        mElapsedTime = 0.0;
        mHasElapsedTime = false;
        mRevengeCooldown.clear();
        mPendingMessages.clear();
        srand((unsigned int)time(NULL));
    }

    virtual ~Rf2PuppeteerPlugin() {}

    void Startup(long version)
    {
        LogInit();
        Log("Startup version=%ld base=%p", version, Base());
    }

    void Shutdown()
    {
        Log("Shutdown");
#if defined(DEBUG) || defined(_DEBUG)
        if (gLogFile) {
            EnterCriticalSection(&gLogCs);
            fclose(gLogFile);
            gLogFile = NULL;
            LeaveCriticalSection(&gLogCs);
        }
#endif
    }

    void StartSession()
    {
        Log("StartSession: pending apply");
        mApplyPending = true;
        mPendingMessages.clear();
        mScoringValid = false;
        mLastScoringVehicles.clear();
    }

    void EndSession()
    {
        Log("EndSession");
        mApplyPending = false;
        mPendingMessages.clear();
    }

    bool WantsScoringUpdates() { return true; }

    long WantsTelemetryUpdates() { return 1; } // player-only is enough for mElapsedTime

    void UpdateTelemetry(const TelemInfoV01 &info)
    {
        mElapsedTime = info.mElapsedTime;
        mHasElapsedTime = true;
    }

    bool WantsToDisplayMessage(MessageInfoV01 &msgInfo)
    {
        if (mPendingMessages.empty()) return false;
        memset(&msgInfo, 0, sizeof(msgInfo));
        strncpy(msgInfo.mText, mPendingMessages.front().c_str(), sizeof(msgInfo.mText) - 1);
        msgInfo.mText[sizeof(msgInfo.mText) - 1] = '\0';
        msgInfo.mDestination = 0; // message center
        msgInfo.mTranslate = 0;
        mPendingMessages.erase(mPendingMessages.begin());
        Log("DisplayMessage: %s", msgInfo.mText);
        return true;
    }

    void UpdateScoring(const ScoringInfoV01 &info)
    {
        // cache scoring
        mLastScoring = info;
        mLastScoringVehicles.clear();
        for (long i = 0; i < info.mNumVehicles && i < 128; ++i) {
            if (!info.mVehicle) break;
            ScoringOrder o;
            o.name = info.mVehicle[i].mDriverName;
            o.place = (int)info.mVehicle[i].mPlace;
            o.isPlayer = info.mVehicle[i].mIsPlayer != 0;
            mLastScoringVehicles.push_back(o);
        }
        mScoringValid = true;
        mLastSession = info.mSession;

        if (mApplyPending) {
            // wait until we have vehicles
            if (info.mNumVehicles > 0) {
                if (mAppliedSession != info.mSession) {
                    ApplyNow(info);
                    mAppliedSession = info.mSession;
                }
                mApplyPending = false;
            }
        }

        HandleRevenge(info);
    }

    bool GetCustomVariable(long i, CustomVariableV01 &var)
    {
        memset(&var, 0, sizeof(var));
        if (i == 0) {
            strncpy(var.mCaption, VAR_STRENGTH_FIRST, sizeof(var.mCaption) - 1);
            var.mNumSettings = 201; var.mCurrentSetting = mStrengthFirst; return true;
        }
        if (i == 1) {
            strncpy(var.mCaption, VAR_STRENGTH_LAST, sizeof(var.mCaption) - 1);
            var.mNumSettings = 201; var.mCurrentSetting = mStrengthLast; return true;
        }
        if (i == 2) {
            strncpy(var.mCaption, VAR_AGGR_FIRST, sizeof(var.mCaption) - 1);
            var.mNumSettings = 201; var.mCurrentSetting = mAggrFirst; return true;
        }
        if (i == 3) {
            strncpy(var.mCaption, VAR_AGGR_LAST, sizeof(var.mCaption) - 1);
            var.mNumSettings = 201; var.mCurrentSetting = mAggrLast; return true;
        }
        if (i == 4) {
            strncpy(var.mCaption, VAR_REVENGE, sizeof(var.mCaption) - 1);
            var.mNumSettings = 201; var.mCurrentSetting = ClampI(mRevenge, 0, 200); return true;
        }
        if (i == 5) {
            strncpy(var.mCaption, VAR_REVENGE_STRENGTH, sizeof(var.mCaption) - 1);
            var.mNumSettings = 201; var.mCurrentSetting = ClampI(mRevengeStrength, 0, 200); return true;
        }
        if (i == 6) {
            strncpy(var.mCaption, VAR_REVENGE_AGGR, sizeof(var.mCaption) - 1);
            var.mNumSettings = 201; var.mCurrentSetting = ClampI(mRevengeAggr, 0, 200); return true;
        }
        if (i == 7) {
            strncpy(var.mCaption, VAR_REVENGE_COOLDOWN, sizeof(var.mCaption) - 1);
            var.mNumSettings = 601; var.mCurrentSetting = ClampI(mRevengeCooldownSec, 0, 600); return true;
        }
        if (i == 8) {
            strncpy(var.mCaption, VAR_REVENGE_BOTS, sizeof(var.mCaption) - 1);
            var.mNumSettings = 65; var.mCurrentSetting = ClampI(mRevengeBots, 0, 64); return true;
        }
        return false;
    }

    void AccessCustomVariable(CustomVariableV01 &var)
    {
        std::string name = Trim(std::string(var.mCaption));
        int val = var.mCurrentSetting;

        if (name == VAR_STRENGTH_FIRST) {
            mStrengthFirst = ClampI(val, 0, 200);
            var.mCurrentSetting = mStrengthFirst;
            Log("CustomVar %s=%d", VAR_STRENGTH_FIRST, mStrengthFirst);
        } else if (name == VAR_STRENGTH_LAST) {
            mStrengthLast = ClampI(val, 0, 200);
            var.mCurrentSetting = mStrengthLast;
            Log("CustomVar %s=%d", VAR_STRENGTH_LAST, mStrengthLast);
        } else if (name == VAR_AGGR_FIRST) {
            mAggrFirst = ClampI(val, 0, 200);
            var.mCurrentSetting = mAggrFirst;
            Log("CustomVar %s=%d", VAR_AGGR_FIRST, mAggrFirst);
        } else if (name == VAR_AGGR_LAST) {
            mAggrLast = ClampI(val, 0, 200);
            var.mCurrentSetting = mAggrLast;
            Log("CustomVar %s=%d", VAR_AGGR_LAST, mAggrLast);
        } else if (name == VAR_REVENGE) {
            mRevenge = ClampI(val, 0, 200);
            var.mCurrentSetting = mRevenge;
            Log("CustomVar %s=%d", VAR_REVENGE, mRevenge);
        } else if (name == VAR_REVENGE_STRENGTH) {
            mRevengeStrength = ClampI(val, 0, 200);
            var.mCurrentSetting = mRevengeStrength;
            Log("CustomVar %s=%d", VAR_REVENGE_STRENGTH, mRevengeStrength);
        } else if (name == VAR_REVENGE_AGGR) {
            mRevengeAggr = ClampI(val, 0, 200);
            var.mCurrentSetting = mRevengeAggr;
            Log("CustomVar %s=%d", VAR_REVENGE_AGGR, mRevengeAggr);
        } else if (name == VAR_REVENGE_COOLDOWN) {
            mRevengeCooldownSec = ClampI(val, 0, 600);
            var.mCurrentSetting = mRevengeCooldownSec;
            Log("CustomVar %s=%d", VAR_REVENGE_COOLDOWN, mRevengeCooldownSec);
        } else if (name == VAR_REVENGE_BOTS) {
            mRevengeBots = ClampI(val, 0, 64);
            var.mCurrentSetting = mRevengeBots;
            Log("CustomVar %s=%d", VAR_REVENGE_BOTS, mRevengeBots);
        } else {
            Log("CustomVar unknown name='%s' val=%d", name.c_str(), val);
        }
    }

    void GetCustomVariableSetting(CustomVariableV01 &var, long i, CustomSettingV01 &setting)
    {
        memset(&setting, 0, sizeof(setting));
        std::string name = Trim(std::string(var.mCaption));
        if (name == VAR_REVENGE && i == 0) {
            strncpy(setting.mName, "Off", sizeof(setting.mName) - 1);
        } else {
            char buf[32];
            _snprintf(buf, sizeof(buf), "%ld", i);
            buf[sizeof(buf) - 1] = '\0';
            strncpy(setting.mName, buf, sizeof(setting.mName) - 1);
        }
    }

private:
    int mStrengthFirst;
    int mStrengthLast;
    int mAggrFirst;
    int mAggrLast;
    int mRevenge;
    int mRevengeStrength;
    int mRevengeAggr;
    int mRevengeCooldownSec;
    int mRevengeBots;
    bool mApplyPending;
    long mAppliedSession;
    double mSessionStartET;
    long mLastSession;
    bool mScoringValid;
    ScoringInfoV01 mLastScoring;
    std::vector<ScoringOrder> mLastScoringVehicles;
    std::map<long, double> mPrevLapDist;             // scoring mID -> last sampled mLapDist
    double mLastRevengeCheckET;
    double mElapsedTime;
    bool mHasElapsedTime;
    std::map<unsigned long long, double> mRevengeCooldown; // obj -> cooldown end ET
    std::map<unsigned long long, int> mAssignedStrength;   // obj -> assigned strength
    std::map<unsigned long long, int> mAssignedAggr;       // obj -> assigned aggr
    std::vector<std::string> mPendingMessages;

    void QueueRevengeMessage(const std::string &botName, const std::string &overtakers)
    {
        static const char *phrases[] = {
            "%s is plotting revenge with a spreadsheet.",
            "%s took that personally. Very personally.",
            "%s has entered petty mode.",
            "%s just activated villain arc DLC.",
            "%s is now fueled by spite and questionable aero.",
            "%s remembered that overtake. All of it.",
            "%s says: 'I hope you like mirrors full of me.'",
            "%s has filed an appeal with the Ministry of Payback.",
            "%s went from race mode to grudge mode.",
            "%s is cooking revenge. It's overcooked."
        };
        const int phraseCount = (int)(sizeof(phrases) / sizeof(phrases[0]));
        int idx = rand() % phraseCount;
        char msg[128];
        _snprintf(msg, sizeof(msg), phrases[idx], botName.c_str());
        msg[sizeof(msg) - 1] = '\0';
        mPendingMessages.push_back(std::string(msg));
        Log("RevengeMsg queued: %s (overtakers=%s)", msg, overtakers.c_str());
    }

    void HandleRevenge(const ScoringInfoV01 &info)
    {
        if (!mRevenge) return;
        if (mAppliedSession != info.mSession) return;

        std::vector<AiObject> ais;
        CollectAiObjects(ais);
        if (ais.empty()) return;

        double now = mHasElapsedTime ? mElapsedTime : info.mCurrentET;

        // check cooldowns first
        for (std::map<unsigned long long, double>::iterator it = mRevengeCooldown.begin(); it != mRevengeCooldown.end(); ) {
            if (now >= it->second) {
                unsigned long long obj = it->first;
                int s = 100, a = 50;
                std::map<unsigned long long, int>::iterator sit = mAssignedStrength.find(obj);
                std::map<unsigned long long, int>::iterator ait = mAssignedAggr.find(obj);
                if (sit != mAssignedStrength.end()) s = sit->second;
                if (ait != mAssignedAggr.end()) a = ait->second;
                std::string baseName; int nameIndex = -1;
                for (size_t k = 0; k < ais.size(); ++k) {
                    if (ais[k].obj == obj) { baseName = ais[k].baseName; nameIndex = ais[k].nameIndex; break; }
                }
                SetObjStrengthAggr(obj, s, a, true, baseName, nameIndex);
                Log("Revenge end %s obj=%llx -> str=%d aggr=%d", baseName.empty() ? "?" : baseName.c_str(), obj, s, a);
                std::map<unsigned long long, double>::iterator eraseIt = it++;
                mRevengeCooldown.erase(eraseIt);
            } else {
                ++it;
            }
        }

        if (mRevengeBots <= 0) return;

        // Overtake detection once every 5 seconds.
        if (now - mLastRevengeCheckET < 5.0) return;
        mLastRevengeCheckET = now;

        if (now - mSessionStartET < 120.0) {
            Log("RevengeCheck skip: sessionStart+120s not reached (et=%.1f start=%.1f)", now, mSessionStartET);
            return;
        }
        Log("RevengeCheck et=%.1f active=%d maxBots=%d", now, (int)mRevengeCooldown.size(), ClampI(mRevengeBots, 0, 64));

        const double trackLen = info.mLapDist;
        const bool useProgress = (trackLen > 1.0);

        struct VehDelta {
            double prevProg;
            double curProg;
            int prevPlace;
            int curPlace;
            bool isPlayer;
            char control;
            const char *name;
        };
        std::map<long, VehDelta> deltas;
        for (long i = 0; i < info.mNumVehicles && i < 128; ++i) {
            if (!info.mVehicle) break;
            const VehicleScoringInfoV01 &v = info.mVehicle[i];
            double curProg;
            if (useProgress) {
                curProg = (double)v.mTotalLaps * trackLen + v.mLapDist;
            } else {
                curProg = 1000000.0 - (double)v.mPlace; // fallback: higher is better
            }
            double prevProg = curProg;
            std::map<long, double>::iterator pit = mPrevLapDist.find(v.mID);
            if (pit != mPrevLapDist.end()) prevProg = pit->second;

            VehDelta d;
            d.prevProg = prevProg; d.curProg = curProg;
            d.prevPlace = (int)v.mPlace; d.curPlace = (int)v.mPlace;
            d.isPlayer = v.mIsPlayer != 0; d.control = v.mControl; d.name = v.mDriverName;
            deltas[v.mID] = d;
        }

        // detect overtakes for local AI by relative progress
        for (long i = 0; i < info.mNumVehicles && i < 128; ++i) {
            if (!info.mVehicle) break;
            const VehicleScoringInfoV01 &v = info.mVehicle[i];
            std::map<long, VehDelta>::iterator dit = deltas.find(v.mID);
            if (dit == deltas.end()) continue;
            const VehDelta &d = dit->second;

            if (d.isPlayer || d.control != 1) {
                mPrevLapDist[v.mID] = d.curProg;
                continue;
            }

            bool overtaken = false;
            bool overtakenByPlayer = false;
            std::string overtakers;

            bool botWrapped = (useProgress && trackLen > 1.0 && d.curProg < d.prevProg - trackLen * 0.5);
            if (botWrapped) {
                Log("RevengeEval %s place=%d prog %.1f->%.1f wrap=1 ignored", v.mDriverName, d.curPlace, d.prevProg, d.curProg);
            } else {
                for (std::map<long, VehDelta>::iterator oi = deltas.begin(); oi != deltas.end(); ++oi) {
                    if (oi->first == v.mID) continue;
                    const VehDelta &o = oi->second;
                    bool otherWrapped = (useProgress && trackLen > 1.0 && (o.curProg < o.prevProg - trackLen * 0.5 || o.curProg > o.prevProg + trackLen * 1.5));
                    if (otherWrapped) continue;
                    if (o.prevProg <= d.prevProg - 2.0 && o.curProg >= d.curProg + 2.0) {
                        overtaken = true;
                        if (o.isPlayer) overtakenByPlayer = true;
                        if (!overtakers.empty()) overtakers += ",";
                        overtakers += o.name ? o.name : "?";
                    }
                }
                Log("RevengeEval %s place=%d prog %.1f->%.1f overtaken=%d byPlayer=%d by=%s",
                    v.mDriverName, d.curPlace, d.prevProg, d.curProg, overtaken ? 1 : 0, overtakenByPlayer ? 1 : 0,
                    overtakers.empty() ? "-" : overtakers.c_str());
            }

            if (overtaken) {
                Log("Overtake %s prog %.1f->%.1f place=%d byPlayer=%d by=%s", v.mDriverName, d.prevProg, d.curProg, d.curPlace, overtakenByPlayer ? 1 : 0, overtakers.c_str());
                bool matched = false;
                for (size_t k = 0; k < ais.size(); ++k) {
                    if (MatchName(ais[k].name, v.mDriverName) || MatchName(ais[k].baseName, v.mDriverName)) {
                        matched = true;
                        unsigned long long obj = ais[k].obj;
                        if (mRevengeCooldown.find(obj) != mRevengeCooldown.end()) {
                            Log("Revenge skip %s already active", ais[k].baseName.c_str());
                            break;
                        }
                        int active = (int)mRevengeCooldown.size();
                        int maxBots = ClampI(mRevengeBots, 0, 64);
                        if (!overtakenByPlayer && active >= maxBots) {
                            Log("Revenge skip %s cap reached (%d/%d active)", ais[k].baseName.c_str(), active, maxBots);
                            break;
                        }
                        int rvS = ClampI(mRevengeStrength, 0, 200);
                        int rvA = ClampI(mRevengeAggr, 0, 200);
                        int rvCd = ClampI(mRevengeCooldownSec, 0, 600);
                        SetObjStrengthAggr(obj, rvS, rvA, true, ais[k].baseName, ais[k].nameIndex);
                        mRevengeCooldown[obj] = now + (double)rvCd;
                        Log("Revenge start %s prog %.1f->%.1f str=%d aggr=%d cd=%d byPlayer=%d active=%d/%d by=%s",
                            ais[k].baseName.c_str(), d.prevProg, d.curProg, rvS, rvA, rvCd, overtakenByPlayer ? 1 : 0, (int)mRevengeCooldown.size(), maxBots, overtakers.c_str());
                        QueueRevengeMessage(ais[k].baseName.empty() ? ais[k].name : ais[k].baseName, overtakers);
                        break;
                    }
                }
                if (!matched) {
                    Log("Revenge warn %s: overtaken but no AI object matched", v.mDriverName);
                }
            }

            mPrevLapDist[v.mID] = d.curProg;
        }

        for (std::map<long, VehDelta>::iterator it = deltas.begin(); it != deltas.end(); ++it) {
            if (it->second.isPlayer || it->second.control != 1) {
                mPrevLapDist[it->first] = it->second.curProg;
            }
        }
    }

    void SetObjStrengthAggr(unsigned long long obj, int strength, int aggr, bool updateName, const std::string &baseName, int nameIndex)
    {
        float aggrVal = (float)ClampI(aggr, 0, 200) / 100.0f;
        WriteObjF32(obj, F_AGGRESSION, aggrVal);

        float e8f = 0, ecf = 0, f0f = 0;
        bool calibOk = ReadF32(ADDR_CALIB_E8, e8f) && ReadF32(ADDR_CALIB_EC, ecf) && ReadF32(ADDR_CALIB_F0, f0f);
        double e8 = e8f, ec = ecf, f0 = f0f;
        if (calibOk && IsFiniteD(e8) && IsFiniteD(ec) && IsFiniteD(f0) && e8 > 0.0 && ec > 0.0 && f0 > 0.0) {
            float oldStrengthF = 0.0f;
            ReadObjF32(obj, F_STRENGTH_FACTOR, oldStrengthF);
            int oldStrength = StrengthForFactor((double)oldStrengthF, e8, ec, f0);
            if (oldStrength < 0) oldStrength = ClampI(strength, MIN_STRENGTH, MAX_STRENGTH);
            double oldFactor = FactorForStrength(oldStrength, e8, ec, f0);
            double newFactor = FactorForStrength(ClampI(strength, MIN_STRENGTH, MAX_STRENGTH), e8, ec, f0);
            if (IsFiniteD(oldFactor) && oldFactor > 0.0 && IsFiniteD(newFactor)) {
                double ratio = newFactor / oldFactor;
                if (ratio > 10.0) ratio = 10.0;
                if (ratio > 0.0) {
                    float fStrength = 0, fRandom = 0, fTarget = 0, fCurrent = 0, fExtra = 0;
                    ReadObjF32(obj, F_STRENGTH_FACTOR, fStrength);
                    ReadObjF32(obj, F_RANDOM_PRODUCT, fRandom);
                    ReadObjF32(obj, F_TARGET_FACTOR, fTarget);
                    ReadObjF32(obj, F_CURRENT_FACTOR, fCurrent);
                    ReadObjF32(obj, F_EXTRA_FACTOR, fExtra);
                    double newS = ClampD((double)fStrength * ratio, 0.0, 2.0);
                    double newR = ClampD((double)fRandom * ratio, 0.0, 1.0);
                    double rawTarget = (double)fTarget + ((fExtra > 0.0f) ? (double)fExtra : 0.0);
                    double newRawTarget = rawTarget * ratio;
                    double newT = ClampD(newRawTarget < 1.0 ? newRawTarget : 1.0, 0.0, 1.0);
                    double newE = newRawTarget - 1.0; if (newE < 0.0) newE = 0.0;
                    double newC = ClampD((double)fCurrent * ratio, 0.0, 1.0);
                    WriteObjF32(obj, F_STRENGTH_FACTOR, (float)newS);
                    WriteObjF32(obj, F_RANDOM_PRODUCT, (float)newR);
                    WriteObjF32(obj, F_TARGET_FACTOR, (float)newT);
                    WriteObjF32(obj, F_CURRENT_FACTOR, (float)newC);
                    WriteObjF32(obj, F_EXTRA_FACTOR, (float)newE);
                }
            }
        }
        if (updateName) {
            if (nameIndex >= 0) {
                bool ok = WriteName(obj, nameIndex, baseName, strength, aggr);
                Log("Name obj=%llx base='%s' idx=%d -> %d,%d ok=%d", obj, baseName.c_str(), nameIndex, strength, aggr, ok ? 1 : 0);
            } else {
                Log("Name obj=%llx base='%s' idx=%d SKIP", obj, baseName.c_str(), nameIndex);
            }
        }
    }

    void ApplyNow(const ScoringInfoV01 &info)
    {
        int sMin = ClampI(mStrengthFirst, 0, 200);
        int sMax = ClampI(mStrengthLast, 0, 200);
        int aMin = ClampI(mAggrFirst, 0, 200);
        int aMax = ClampI(mAggrLast, 0, 200);
        Log("Apply session=%ld Strength %d-%d Aggr %d-%d Revenge=%d RStr=%d RAgr=%d RCd=%d RBots=%d", info.mSession, sMin, sMax, aMin, aMax, mRevenge, mRevengeStrength, mRevengeAggr, mRevengeCooldownSec, mRevengeBots);
        mSessionStartET = mHasElapsedTime ? mElapsedTime : info.mCurrentET;
        mRevengeCooldown.clear();
        mAssignedStrength.clear();
        mAssignedAggr.clear();
        mPrevLapDist.clear();
        mLastRevengeCheckET = -1000.0;

        std::vector<AiObject> ais;
        CollectAiObjects(ais);
        if (ais.empty()) {
            Log("No AI objects found");
            return;
        }

        bool isPractice = (info.mSession >= 0 && info.mSession <= 4);
        std::vector<ScoringOrder> order = mLastScoringVehicles;

        // build list of AI with place (grid/start order: first on grid gets first range number)
        struct AiAssign {
            size_t idx;
            int place;
        };
        std::vector<AiAssign> list;
        for (size_t i = 0; i < ais.size(); ++i) {
            int place = FindScoringPlace(order, ais[i], isPractice, (int)i);
            AiAssign a; a.idx = i; a.place = place;
            list.push_back(a);
        }

        // sort by place ascending (P1 first)
        for (size_t i = 0; i < list.size(); ++i) {
            for (size_t j = i + 1; j < list.size(); ++j) {
                if (list[j].place < list[i].place) {
                    AiAssign t = list[i]; list[i] = list[j]; list[j] = t;
                }
            }
        }

        // read calibration for strength factors
        float e8f = 0, ecf = 0, f0f = 0, d0f = 0;
        bool calibOk = ReadF32(ADDR_CALIB_E8, e8f) && ReadF32(ADDR_CALIB_EC, ecf) && ReadF32(ADDR_CALIB_F0, f0f) && ReadF32(ADDR_CALIB_D0, d0f);
        double e8 = e8f, ec = ecf, f0 = f0f;
        if (!calibOk || !IsFiniteD(e8) || !IsFiniteD(ec) || !IsFiniteD(f0) || e8 <= 0.0 || ec <= 0.0 || f0 <= 0.0) {
            Log("Bad calibration constants; cannot set strength factors");
            calibOk = false;
        }

        int count = (int)list.size();
        for (int rank = 0; rank < count; ++rank) {
            AiObject &ai = ais[list[rank].idx];
            double t = (count <= 1) ? 0.0 : ((double)rank / (double)(count - 1)); // 0=pole, 1=back
            int strength = (int)floor((double)sMin + ((double)sMax - (double)sMin) * t + 0.5);
            int aggr = (int)floor((double)aMin + ((double)aMax - (double)aMin) * t + 0.5);
            strength = ClampI(strength, 0, 200);
            aggr = ClampI(aggr, 0, 200);

            // aggression
            float aggrVal = (float)aggr / 100.0f;
            WriteObjF32(ai.obj, F_AGGRESSION, aggrVal);
            mAssignedStrength[ai.obj] = strength;
            mAssignedAggr[ai.obj] = aggr;

            // strength factors
            if (calibOk) {
                float oldStrengthF = 0.0f;
                ReadObjF32(ai.obj, F_STRENGTH_FACTOR, oldStrengthF);
                int oldStrength = StrengthForFactor((double)oldStrengthF, e8, ec, f0);
                if (oldStrength < 0) oldStrength = ClampI(strength, MIN_STRENGTH, MAX_STRENGTH);

                double oldFactor = FactorForStrength(oldStrength, e8, ec, f0);
                double newFactor = FactorForStrength(ClampI(strength, MIN_STRENGTH, MAX_STRENGTH), e8, ec, f0);
                if (IsFiniteD(oldFactor) && oldFactor > 0.0 && IsFiniteD(newFactor)) {
                    double ratio = newFactor / oldFactor;
                    if (ratio > 10.0) ratio = 10.0;
                    if (ratio > 0.0) {
                        float fStrength = 0, fRandom = 0, fTarget = 0, fCurrent = 0, fExtra = 0;
                        ReadObjF32(ai.obj, F_STRENGTH_FACTOR, fStrength);
                        ReadObjF32(ai.obj, F_RANDOM_PRODUCT, fRandom);
                        ReadObjF32(ai.obj, F_TARGET_FACTOR, fTarget);
                        ReadObjF32(ai.obj, F_CURRENT_FACTOR, fCurrent);
                        ReadObjF32(ai.obj, F_EXTRA_FACTOR, fExtra);

                        double newS = ClampD((double)fStrength * ratio, 0.0, 2.0);
                        double newR = ClampD((double)fRandom * ratio, 0.0, 1.0);
                        double rawTarget = (double)fTarget + ((fExtra > 0.0f) ? (double)fExtra : 0.0);
                        double newRawTarget = rawTarget * ratio;
                        double newT = ClampD(newRawTarget < 1.0 ? newRawTarget : 1.0, 0.0, 1.0);
                        double newE = newRawTarget - 1.0; if (newE < 0.0) newE = 0.0;
                        double newC = ClampD((double)fCurrent * ratio, 0.0, 1.0);

                        WriteObjF32(ai.obj, F_STRENGTH_FACTOR, (float)newS);
                        WriteObjF32(ai.obj, F_RANDOM_PRODUCT, (float)newR);
                        WriteObjF32(ai.obj, F_TARGET_FACTOR, (float)newT);
                        WriteObjF32(ai.obj, F_CURRENT_FACTOR, (float)newC);
                        WriteObjF32(ai.obj, F_EXTRA_FACTOR, (float)newE);
                    }
                }
            }

            // name
            bool nameOk = false;
            if (ai.nameIndex >= 0) {
                nameOk = WriteName(ai.obj, ai.nameIndex, ai.baseName.empty() ? ai.name : ai.baseName, strength, aggr);
            }
            Log("AI rank=%d place=%d %s name='%s' -> str=%d aggr=%d nameOk=%d",
                rank + 1, list[rank].place, ai.label.c_str(), ai.baseName.c_str(), strength, aggr, nameOk ? 1 : 0);
        }

        // Do not touch UI settings: global aggression / slot strength.

        Log("Apply done: %d AI drivers", count);
    }
};


extern "C" __declspec(dllexport) const char * __cdecl GetPluginName()
{
    return PLUGIN_NAME;
}

extern "C" __declspec(dllexport) PluginObjectType __cdecl GetPluginType()
{
    return PO_INTERNALS;
}

extern "C" __declspec(dllexport) int __cdecl GetPluginVersion()
{
    return 7;
}

extern "C" __declspec(dllexport) PluginObject * __cdecl CreatePluginObject()
{
    return new Rf2PuppeteerPlugin();
}

extern "C" __declspec(dllexport) void __cdecl DestroyPluginObject(PluginObject *obj)
{
    delete obj;
}
