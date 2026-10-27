#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <unordered_set>
#include <vector>

using namespace std;

// URL normalization: makes "HTTP://WWW.Evil.com/" == "evil.com"
string normalizeUrl(string url) {
    size_t b = url.find_first_not_of(" \t\r\n");
    size_t e = url.find_last_not_of(" \t\r\n");
    if (b == string::npos) return "";
    url = url.substr(b, e - b + 1);

    for (char &c : url) c = (char)tolower((unsigned char)c);

    size_t p = url.find("://");
    if (p != string::npos) url = url.substr(p + 3);

    if (url.rfind("www.", 0) == 0) url = url.substr(4);

    while (!url.empty() && url.back() == '/') url.pop_back();

    return url;
}
class BloomFilter {
private:
    vector<uint64_t> bits;
    size_t m;
    int k;
    size_t itemsInserted;

    static uint64_t fnv1a(const string &s) {
        uint64_t h = 1469598103934665603ULL;
        for (unsigned char c : s) {
            h ^= c;
            h *= 1099511628211ULL;
        }
        return h;
    }

    static uint64_t djb2(const string &s) {
        uint64_t h = 5381;
        for (unsigned char c : s) h = ((h << 5) + h) + c;
        h ^= h >> 33;
        h *= 0xff51afd7ed558ccdULL;
        h ^= h >> 33;
        return h | 1ULL;
    }

    inline void setBit(size_t i)        { bits[i >> 6] |= (1ULL << (i & 63)); }
    inline bool getBit(size_t i) const  { return (bits[i >> 6] >> (i & 63)) & 1ULL; }

public:
    BloomFilter(size_t expectedItems, double fpRate) : itemsInserted(0) {
        if (expectedItems == 0) expectedItems = 1;
        if (fpRate <= 0.0 || fpRate >= 1.0) fpRate = 0.01;
        double ln2 = log(2.0);
        m = (size_t)ceil(-(double)expectedItems * log(fpRate) / (ln2 * ln2));
        if (m < 64) m = 64;
        k = (int)round((double)m / (double)expectedItems * ln2);
        if (k < 1) k = 1;
        bits.assign((m + 63) / 64, 0ULL);
    }

    void insert(const string &item) {
        uint64_t h1 = fnv1a(item), h2 = djb2(item);
        for (int i = 0; i < k; i++) setBit((h1 + (uint64_t)i * h2) % m);
        itemsInserted++;
    }

    bool possiblyContains(const string &item) const {
        uint64_t h1 = fnv1a(item), h2 = djb2(item);
        for (int i = 0; i < k; i++)
            if (!getBit((h1 + (uint64_t)i * h2) % m)) return false;
        return true;
    }

    size_t bitCount() const { return m; }
    int hashCount() const { return k; }
    size_t inserted() const { return itemsInserted; }
    size_t memoryBytes() const { return bits.size() * sizeof(uint64_t); }

    size_t bitsSet() const {
        size_t c = 0;
        for (uint64_t w : bits) c += __builtin_popcountll(w);
        return c;
    }

    double estimatedFpRate() const {
        return pow(1.0 - exp(-(double)k * (double)itemsInserted / (double)m), k);
    }
};
class UrlPreFilter {
private:
    BloomFilter bloom;
    unordered_set<string> exactDb;

public:
    UrlPreFilter(size_t expectedItems, double fpRate) : bloom(expectedItems, fpRate) {}

    bool addMalicious(const string &raw) {
        string u = normalizeUrl(raw);
        if (u.empty()) return false;
        bloom.insert(u);
        exactDb.insert(u);
        return true;
    }

    int check(const string &raw, bool &bloomSaidMaybe) const {
        string u = normalizeUrl(raw);
        bloomSaidMaybe = false;
        if (u.empty()) return 0;
        if (!bloom.possiblyContains(u)) return 0;
        bloomSaidMaybe = true;
        return exactDb.count(u) ? 1 : 2;
    }

    const BloomFilter &filter() const { return bloom; }
    size_t exactSize() const { return exactDb.size(); }
};

static void loadFile(UrlPreFilter &f, const string &path) {
    ifstream in(path);
    if (!in) { cout << "  Could not open file: " << path << "\n"; return; }
    string line;
    size_t cnt = 0;
    while (getline(in, line))
        if (f.addMalicious(line)) cnt++;
    cout << "  Loaded " << cnt << " URLs from " << path << "\n";
}

static void loadSampleData(UrlPreFilter &f) {
    const vector<string> bad = {
        "http://free-gift-cards.xyz/claim",
        "http://paypa1-secure-login.com/verify",
        "https://www.bank-update-info.net/login.php",
        "http://malware-download.ru/setup.exe",
        "http://win-a-prize-now.top/",
        "https://secure-appleid-verify.co/signin",
        "http://crypto-doubler.biz/invest",
        "http://phish-me.tk/office365",
        "http://dl.free-software-crack.info/key.zip",
        "http://account-suspended-alert.cc/restore"
    };
    for (const string &u : bad) f.addMalicious(u);
    cout << "  Loaded " << bad.size() << " sample malicious URLs.\n";
}
static void printResult(const string &url, int r, bool maybe) {
    cout << "  URL : " << url << "\n";
    if (r == 0)
        cout << "  Result : SAFE  (Bloom filter: definitely NOT in malicious set -> no further check needed)\n";
    else if (r == 1)
        cout << "  Result : MALICIOUS  (Bloom filter said 'maybe' and second-stage check CONFIRMED)\n";
    else
        cout << "  Result : FALSE POSITIVE  (Bloom filter said 'maybe' but second-stage check cleared it)\n";
    (void)maybe;
}

static void showStats(const UrlPreFilter &f) {
    const BloomFilter &b = f.filter();
    size_t set = b.bitsSet();
    cout << fixed << setprecision(4);
    cout << "  Bit array size (m)        : " << b.bitCount() << " bits (" << b.memoryBytes() << " bytes)\n";
    cout << "  Hash functions (k)        : " << b.hashCount() << "\n";
    cout << "  URLs inserted (n)         : " << b.inserted() << "\n";
    cout << "  Bits set                  : " << set << "  (fill ratio "
         << (double)set / (double)b.bitCount() << ")\n";
    cout << "  Theoretical FP rate       : " << b.estimatedFpRate() << "\n";
    cout << "  Memory per URL (at n)     : "
         << (b.inserted() ? (double)b.bitCount() / (double)b.inserted() : 0.0) << " bits\n";
}

static void empiricalFpTest(size_t n, double p, size_t trials) {
    UrlPreFilter f(n, p);
    mt19937_64 rng(12345);
    const string alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
    auto randomUrl = [&](const string &prefix, size_t id) {
        string u = prefix;
        for (int i = 0; i < 12; i++) u += alphabet[rng() % alphabet.size()];
        return u + ".com/p" + to_string(id);
    };
    for (size_t i = 0; i < n; i++) f.addMalicious(randomUrl("bad-", i));

    size_t falsePos = 0;
    for (size_t t = 0; t < trials; t++) {
        bool maybe;
        if (f.check(randomUrl("safe-", t), maybe) == 2) falsePos++;
    }
    cout << fixed << setprecision(4);
    cout << "  Filled with " << n << " random malicious URLs (m=" << f.filter().bitCount()
         << ", k=" << f.filter().hashCount() << ")\n";
    cout << "  Tested " << trials << " safe URLs -> " << falsePos << " false positives\n";
    cout << "  Empirical FP rate   : " << (double)falsePos / (double)trials << "\n";
    cout << "  Theoretical FP rate : " << f.filter().estimatedFpRate() << "\n";
}

int main(int argc, char *argv[]) {
    size_t expectedItems = 1000;
    double fpRate = 0.01;

    cout << "=== Malicious URL Pre-Filter (Bloom Filter) ===\n";
    cout << "Expected number of malicious URLs [default 1000]: ";
    string s;
    getline(cin, s);
    if (!s.empty()) {
        try { expectedItems = stoull(s); } catch (...) { cout << "  Invalid, using 1000\n"; }
        if (expectedItems == 0) expectedItems = 1000;
    }
    cout << "Target false-positive rate [default 0.01]: ";
    getline(cin, s);
    if (!s.empty()) {
        try { fpRate = stod(s); } catch (...) { cout << "  Invalid, using 0.01\n"; }
        if (fpRate <= 0.0 || fpRate >= 1.0) { fpRate = 0.01; cout << "  Out of range, using 0.01\n"; }
    }

    UrlPreFilter filter(expectedItems, fpRate);
    cout << "Filter created: m=" << filter.filter().bitCount()
         << " bits, k=" << filter.filter().hashCount() << "\n";

    if (argc > 1) loadFile(filter, argv[1]);

    while (true) {
        cout << "\n--- MENU ---\n"
             << " 1. Add malicious URL\n"
             << " 2. Check a URL\n"
             << " 3. Load sample malicious URLs\n"
             << " 4. Load malicious URLs from file\n"
             << " 5. Show filter statistics\n"
             << " 6. Run false-positive experiment (fresh filter at full capacity)\n"
             << " 7. Exit\n"
             << "Choice: ";
        if (!getline(cin, s)) break;

        int ch = 0;
        try { ch = stoi(s); } catch (...) { cout << "  Please enter a number 1-7.\n"; continue; }

        if (ch == 1) {
            cout << "  Enter URL: ";
            getline(cin, s);
            if (filter.addMalicious(s)) cout << "  Added: " << normalizeUrl(s) << "\n";
            else cout << "  Empty URL ignored.\n";
        } else if (ch == 2) {
            cout << "  Enter URL to check: ";
            getline(cin, s);
            if (normalizeUrl(s).empty()) { cout << "  Empty URL ignored.\n"; continue; }
            bool maybe;
            int r = filter.check(s, maybe);
            printResult(s, r, maybe);
        } else if (ch == 3) {
            loadSampleData(filter);
        } else if (ch == 4) {
            cout << "  File path: ";
            getline(cin, s);
            loadFile(filter, s);
        } else if (ch == 5) {
            showStats(filter);
        } else if (ch == 6) {
            empiricalFpTest(expectedItems, fpRate, 100000);
        } else if (ch == 7) {
            cout << "Goodbye.\n";
            break;
        } else {
            cout << "  Please enter a number 1-7.\n";
        }
    }
    return 0;
}