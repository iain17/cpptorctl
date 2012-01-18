
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/regex.hpp>
#include <boost/foreach.hpp>
#include <boost/cstdint.hpp>

#include "TorUtil.hpp"

static const char rcsid[] =
    "$Id$";

TorUtil::BufSock::BufSock(tcp::socket& s) :
    _s(s)
{
}

std::string
TorUtil::BufSock::readline()
{
    string result;
    if (_buf.size() > 0) {
        size_t idx = _buf[0].find('\n');
        if (idx != string::npos) {
            result = _buf[0].substr(0, idx+1);
            _buf[0].erase(0, idx+1);
            return result;
        }
    }
    // can't find a newline, so read more
    while (true) {
        char carray[128] = {0};
        boost::system::error_code error;

        size_t len = _s.read_some(boost::asio::buffer(carray), error);
        if (error == boost::asio::error::eof) {
            return result; // Connection closed cleanly by peer.
        }
        else if (error) {
            throw boost::system::system_error(error); // Some other error.
        }
        
        if (len == 0) {
            return result;
        }
        string s(carray, len);
        size_t idx = s.find('\n');
        if (idx != string::npos) {
            _buf.push_back(s.substr(0, idx+1));
            for (vector<string>::iterator it = _buf.begin();
                 it != _buf.end(); ++it) {
                result += *it;
            }
            string rest = s.substr(idx+1);
            _buf.clear();
            if (rest.length() > 0) {
                _buf.push_back(rest);
            }
            return result;
        }
        else {
            _buf.push_back(s);
        }
    }
}

void
TorUtil::BufSock::write(const string& s)
{
    /* this call blocks until "All of the data in the supplied buffers
     * has been written."
     */
    size_t numsent = boost::asio::write(_s, boost::asio::buffer(s));
    /* but checking anyway */
    assert (numsent == s.length());
}

void
TorUtil::BufSock::close()
{
    _s.close();
}

string
TorUtil::unescape_dots(const string& s, bool translate_nl)
{
    vector<string> lines;
    static const boost::regex e( "\r\n" );
    boost::algorithm::split_regex(lines, s, e);
    
    BOOST_FOREACH(string &line, lines) {
        if (boost::starts_with(line, ".")) {
            line = line.substr(1);
        }
    }
    
    if (lines.size() > 0 && lines.back().length() > 0) {
        lines.push_back("");
    }
    
    if (translate_nl) {
        return boost::join(lines, "\n");
    }
    else {
        return boost::join(lines, "\r\n");
    }
}

vector<string>
TorUtil::split(const string& s, const string& sep, int maxsplit)
{
    /* this is a portion of python's stringobject.c::string_split() */
    assert (!sep.empty());
    vector<string> result;

    size_t len = s.length(), n, i, j;
    if (maxsplit < 0) {
        maxsplit = std::numeric_limits<int>::max();
    }

    n = sep.length();

    i = j = 0;
    while ((j+n <= len) && (maxsplit-- > 0)) {
        for (; j+n <= len; j++) {
            if (s.find(sep, j) == j) {
                result.push_back(s.substr(i, j-i));
                i = j = j + n;
                break;
            }
        }
    }
    result.push_back(s.substr(i, len));
    return result;
}

/////////////////////////////
/* base64 encoding/decoding.
 * 
 * shamelessly borrowed from python's binascii.c.
 * the testing borrowed/ported from test_binascii.py.
 */
static const char table_a2b_base64[] = {
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,62, -1,-1,-1,63,
    52,53,54,55, 56,57,58,59, 60,61,-1,-1, -1, 0,-1,-1, /* Note PAD->0 */
    -1, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,-1, -1,-1,-1,-1,
    -1,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,-1, -1,-1,-1,-1
};
  
#define BASE64_PAD '='

static const unsigned char table_b2a_base64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int
binascii_find_valid(const unsigned char *s, ssize_t slen, int num)
{            
    /* Finds & returns the (num+1)th
    ** valid character for base64, or -1 if none.
    */

    int ret = -1;
    unsigned char c, b64val;

    while ((slen > 0) && (ret == -1)) {
        c = *s;
        b64val = table_a2b_base64[c & 0x7f];
        if ( ((c <= 0x7f) && (b64val != (unsigned char)-1)) ) {
            if (num == 0)
                ret = *s;
            num--;
        }

        s++;
        slen--;
    }
    return ret;
}

string
TorUtil::decode_base64(const string& s)
{
    const unsigned char *ascii_data;
    string bin_data;
    int leftbits = 0;
    unsigned char this_ch;
    unsigned int leftchar = 0;
    size_t ascii_len, bin_len;
    int quad_pos = 0;

    ascii_data = (unsigned char*)s.c_str();
    ascii_len = s.length();

    assert(ascii_len >= 0);

    bin_len = ((ascii_len+3)/4)*3; /* Upper bound, corrected later */

    /* Allocate the buffer */
    bin_data = string(bin_len, char());
    bin_len = 0;

    for( ; ascii_len > 0; ascii_len--, ascii_data++) {
        this_ch = *ascii_data;

        if (this_ch > 0x7f ||
            this_ch == '\r' || this_ch == '\n' || this_ch == ' ')
            continue;

        /* Check for pad sequences and ignore
        ** the invalid ones.
        */
        if (this_ch == BASE64_PAD) {
            if ( (quad_pos < 2) ||
                 ((quad_pos == 2) &&
                  (binascii_find_valid(ascii_data, ascii_len, 1)
                   != BASE64_PAD)) )
            {
                continue;
            }
            else {
                /* A pad sequence means no more input.
                ** We've already interpreted the data
                ** from the quad at this point.
                */
                leftbits = 0;
                break;
            }
        }

        this_ch = table_a2b_base64[*ascii_data];
        if ( this_ch == (unsigned char) -1 )
            continue;

        /*
        ** Shift it in on the low end, and see if there's
        ** a byte ready for output.
        */
        quad_pos = (quad_pos + 1) & 0x03;
        leftchar = (leftchar << 6) | (this_ch);
        leftbits += 6;

        if ( leftbits >= 8 ) {
            leftbits -= 8;
            bin_data[bin_len++] = (leftchar >> leftbits) & 0xff;
            leftchar &= ((1 << leftbits) - 1);
        }
    }

    if (leftbits != 0) {
        return "";
    }

    /* And set string size correctly. If the result string is empty
    ** (because the input was all invalid) return the shared empty
    ** string instead; _PyString_Resize() won't do this for us.
    */
    if (bin_len > 0)
    {
        bin_data.resize(bin_len);
    }
    else {
       bin_data = "";
    }
    return bin_data;
}

string
TorUtil::encode_base64(const string& s)
{
    unsigned char *ascii_data, *saved_ascii_data;
    const unsigned char *bin_data;
    int leftbits = 0;
    unsigned char this_ch;
    unsigned int leftchar = 0;
    string rv;
    size_t bin_len;

    bin_data = (const unsigned char*)s.c_str();
    bin_len = s.length();

    assert(bin_len >= 0);

    /* We're lazy and allocate too much (fixed up later).
       "+3" leaves room for up to two pad characters and a trailing
       newline.  Note that 'b' gets encoded as 'Yg==\n' (1 in, 5 out). */
    ascii_data = (unsigned char *)calloc(bin_len*2 + 3, sizeof(unsigned char));
    saved_ascii_data = ascii_data;

    for( ; bin_len > 0 ; bin_len--, bin_data++ ) {
        /* Shift the data into our buffer */
        leftchar = (leftchar << 8) | *bin_data;
        leftbits += 8;

        /* See if there are 6-bit groups ready */
        while ( leftbits >= 6 ) {
            this_ch = (leftchar >> (leftbits-6)) & 0x3f;
            leftbits -= 6;
            *ascii_data++ = table_b2a_base64[this_ch];
        }
    }
    if ( leftbits == 2 ) {
        *ascii_data++ = table_b2a_base64[(leftchar&3) << 4];
        *ascii_data++ = BASE64_PAD;
        *ascii_data++ = BASE64_PAD;
    } else if ( leftbits == 4 ) {
        *ascii_data++ = table_b2a_base64[(leftchar&0xf) << 2];
        *ascii_data++ = BASE64_PAD;
    }
    *ascii_data++ = '\n';   /* Append a courtesy newline */

    rv = string((char *)saved_ascii_data, ascii_data - saved_ascii_data);
    free(saved_ascii_data);
    return rv;
}

static int
to_int(int c)
{
    if (isdigit(c))
        return c - '0';
    else {
        if (isupper(c))
            c = tolower(c);
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
    }
    return -1;
}

string
TorUtil::decode_hex(const string& s)
{
    const char* argbuf;
    ssize_t arglen;
    string retval;
    ssize_t i, j;

    argbuf = s.c_str();
    arglen = s.length();

    assert(arglen >= 0);

    /* XXX What should we do about strings with an odd length?  Should
     * we add an implicit leading zero, or a trailing zero?  For now,
     * raise an exception.
     */
    if (arglen % 2) {
        throw std::exception(); //"Odd-length string");
    }

    retval = string((arglen/2), char());

    for (i=j=0; i < arglen; i += 2) {
        int top = to_int((argbuf[i]) & 0xff);
        int bot = to_int((argbuf[i+1]) & 0xff);
        if (top == -1 || bot == -1) {
            throw std::exception(); //"Non-hexadecimal digit found");
        }
        retval[j++] = (top << 4) + bot;
    }
    return retval;
}

string
TorUtil::encode_hex(const string& s)
{
    const char* argbuf;
    ssize_t arglen;
    string retval;
    ssize_t i, j;

    argbuf = s.c_str();
    arglen = s.length();

    assert(arglen >= 0);

    retval = string(arglen*2, char());

    /* make hex version of string, taken from shamodule.c */
    for (i=j=0; i < arglen; i++) {
        char c;
        c = (argbuf[i] >> 4) & 0xf;
        c = (c>9) ? c+'a'-10 : c + '0';
        retval[j++] = c;
        c = argbuf[i] & 0xf;
        c = (c>9) ? c+'a'-10 : c + '0';
        retval[j++] = c;
    }
    return retval;
}

#ifdef TESTING
static string data;

void
test_base64valid()
{
    int MAX_BASE64 = 57;
    vector<string> lines;
    for (int i = 0; i < data.length(); i += MAX_BASE64) {
        string b = data.substr(i, MAX_BASE64);
        string a = binascii_b2a_base64(b);
        lines.push_back(a);
    }
    string res = "";
    for (vector<string>::iterator it = lines.begin(); it != lines.end(); it++) {
        string b = binascii_a2b_base64(*it);
        res += b;
    }
    assert (0 == res.compare(data));
}

string
addnoise(string line, const string& fillers)
{
    string noise = fillers;
    int ratio = line.length() / noise.length();
    string res = "";
    char c;
    while (line.length() != 0 && noise.length() != 0) {
        if ((line.length() / noise.length()) > ratio) {
            c = line[0];
            line = line.substr(1);
        }
        else {
            c = noise[0];
            noise = noise.substr(1);
        }
        res += c;
    }
    return res + noise + line;
}

void
test_base64invalid()
{
    int MAX_BASE64 = 57;
    vector<string> lines;
    for (int i = 0; i < data.length(); i += MAX_BASE64) {
        string b = data.substr(i, MAX_BASE64);
        string a = binascii_b2a_base64(b);
        lines.push_back(a);
    }

    string fillers = "";
    string valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";

    for (int i = 0; i < 256; i++) {
        char c = i;
        if (valid.find(c) == string::npos) {
            fillers += c;
        }
    }

    string res = "";
    for (int i = 0; i < lines.size(); i++) {
        string line = addnoise(lines[i], fillers);
        string b = binascii_a2b_base64(line);
        res += b;
    }
    assert(0 == res.compare(data));

    assert(binascii_a2b_base64(fillers) == "");
    return ;
}

void
test_hex()
{
    string s = "{s\005\000\000\000worldi\002\000\000\000s\005\000\000\000helloi\001\000\000\0000";
    string t = binascii_hexlify(s);
    string u = binascii_unhexlify(t);
    assert(s == u);
    // hack to test that exception is thrown
    bool reached = false;
    try {
        binascii_unhexlify(t.substr(t.length()-1));
        reached = true;
    }
    catch (std::exception& e) {
    }
    assert (!reached);
    try {
        binascii_unhexlify(t.substr(t.length()-1)+"q");
        reached = true;
    }
    catch (std::exception& e) {
    }
    assert (!reached);
    return;
}
#endif
