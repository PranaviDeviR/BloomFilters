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