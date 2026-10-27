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