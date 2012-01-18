
#ifndef TORUTIL_HPP
#define TORUTIL_HPP

/* $Id$ */

#include <string>
#include <vector>
#include <boost/asio.hpp>

using namespace boost::asio::ip;
using std::string;
using std::vector;


#include <boost/thread/mutex.hpp>
#include <boost/thread/condition_variable.hpp>

namespace TorUtil {

    class BufSock
    {
    public:
        BufSock(tcp::socket& s);
        string readline();
        void write(const string& s);
        void close();
    private:
        tcp::socket& _s;
        vector<string> _buf;
    };
    
    string unescape_dots(const string& s, bool translate_nl=true);
    
    /* this works like python's string split, except that we do not
     * support the implicit ("any whitespace") separator.
     */
    vector<string> split(const string& s, const string& sep, int maxsplit=-1);

    /* base64/hex encoding/decoding.
     * 
     * shamelessly borrowed from python's binascii.c.
     * the testing borrowed/ported from test_binascii.py.
     */
    /* encode into base64 data */
    string encode_base64(const string& s);
    /* decode from base64 data */
    string decode_base64(const string& s);
    /* encode into hex */
    string encode_hex(const string& s);
    /* decode from hex */
    string decode_hex(const string& s);
}

#endif // TORUTIL_HPP
