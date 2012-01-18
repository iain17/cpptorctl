
#include <boost/make_shared.hpp>
#include <boost/ref.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/foreach.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/assign/list_of.hpp>
#include <set>
#include <openssl/sha.h>
#include <sstream>
#include <boost/make_shared.hpp>

#include "TorCtl.hpp"
#include "common.hpp"
#include "Log.hpp"

using namespace TorCtl;
using boost::regex;
using boost::regex_match;
using boost::regex_search;
using boost::lexical_cast;
using boost::make_shared;
using std::set;
using std::stringstream;
using std::endl;

static const char rcsid[] =
    "$Id$";


#define INIT_CLASS_LOGGER(clsname)                                      \
    log4cxx::LoggerPtr clsname::_logger(                                \
        log4cxx::Logger::getLogger("TorCtl." EXPAND_AND_QUOTE(clsname)))

INIT_CLASS_LOGGER(Connection);
INIT_CLASS_LOGGER(ConsensusTracker);
INIT_CLASS_LOGGER(Router);

/*
 * Parse the body of an NS event or command into a list of
 * NetworkStatus instances.
*/
vector<NetworkStatusPtr >
parse_ns_body(const string& data)
{
    /* verified matching pyctl as of revision 3695. */
    vector<NetworkStatusPtr > nslist;
    if (data.length() == 0) {
        return nslist;
    }
    /* one "nsline" actually might span multiple lines (i.e., contain
     * "\n").
     */
    static const regex nsline_e("^r ");
    boost::sregex_token_iterator nsline(
        data.begin(), data.end(), nsline_e, -1);
    boost::sregex_token_iterator endtoken;

    nsline++;

    while(nsline != endtoken) {
        boost::smatch identity_m, flags_m, bw_m;
        static const regex identity_e(
            "(\\S+)\\s(\\S+)\\s(\\S+)\\s(\\S+\\s\\S+)\\s(\\S+)\\s(\\d+)\\s(\\d+)");
        static const regex flags_e("^s((?:[ ]\\S*)+)");
        static const regex bw_e("^w Bandwidth=(\\d+)");

        // can't use regex_match() on the entire nsline because it
        // requires the entire string to match. we only try to match
        // the first/identity line, so we can either use regex_search,
        // but im using match on just the identity line.
        vector<string> lines = TorUtil::split(nsline->str(), "\n");
        assert(lines.size() >= 2); // identity and flags lines are required

        assert(regex_match(lines[0], identity_m, identity_e));

        string nickname, idhash, orhash, updated, ip, orport, dirport;
        // there's gotta be a better way to do this, something like:
        // tie(nickname, idhash, ...) = m.sub_matches()?
        string* array[] = {
            NULL, &nickname, &idhash, &orhash, &updated, &ip, &orport, &dirport};
        for (size_t i = 1; i < identity_m.size(); ++i) {
            *array[i] = identity_m[i];
        }

        vector<string> flags;
        int bandwidth = -1;

        for (size_t i = 1; i < lines.size(); ++i) {
            if (regex_match(lines[i], flags_m, flags_e)) {
                flags = TorUtil::split(boost::trim_copy(flags_m[1].str()), " ");
            }
            else if (regex_match(lines[i], bw_m, bw_e)) {
                bandwidth = lexical_cast<int>(bw_m[1].str()) * 1000;
            }
        }

        assert(!flags.empty()); // there must be flags

        nslist.push_back(make_shared<NetworkStatus>(
                             nickname, idhash, orhash, updated, ip,
                             lexical_cast<uint16_t>(orport),
                             lexical_cast<uint16_t>(dirport), 
                             flags, bandwidth));
        nsline++;
    }
    return nslist;
}

/*******************************************************/
NetworkStatus::NetworkStatus(
    // checked (bf: breadthfirst).
    const string& nickname, const string& idhash, const string& orhash, const string& updated,
    const string& ip, uint16_t orport, uint16_t dirport, const vector<string>& flags,
    int32_t bandwidth) :
    _nickname(nickname), _idhash(idhash), _orhash(orhash),
    _ip(ip), _orport(orport), _dirport(dirport), _flags(flags), _bandwidth(bandwidth)
{
    _idhex = TorUtil::encode_hex(TorUtil::decode_base64(_idhash + "="));
    boost::algorithm::to_upper(_idhex);

    _updated = time_from_string(updated);
};

/****************/
string
NetworkStatus::toString() const
{
    stringstream s;

#undef ADD_TO_S
#define ADD_TO_S(member)                                                \
    do {                                                                \
        s << (#member ": ") << (_##member) << "\n";                     \
    }                                                                   \
    while (0)

    ADD_TO_S(nickname);
    ADD_TO_S(idhash);
    ADD_TO_S(orhash);
    ADD_TO_S(ip);
    ADD_TO_S(orport);
    ADD_TO_S(dirport);

    s << "flags: " << boost::join(_flags, ",") << "\n";

    ADD_TO_S(idhex);
    ADD_TO_S(bandwidth);

    s << "updated: " << (_updated) << "\n";

#undef ADD_TO_S

    return s.str();
}

/*******************************************************/

Connection::Connection(tcp::socket& sock) :
    _handler(NULL), _closed(false)
{
    // make_shared complains
    _s = shared_ptr<TorUtil::BufSock>(new TorUtil::BufSock(sock));
}

/************/
void
Connection::close()
{
    // Shut down this controller connection
    boost::unique_lock<boost::recursive_mutex> lock(_sendLock);
    try {
        CallbackContext* qi = NULL;
        _queue.put(qi);
        replyPtr emptyreply;
        std::pair<ptime, replyPtr > eqi = std::make_pair(
            microsec_clock::local_time(), emptyreply);
        _eventQueue.put(eqi);
        _closed = true;
        _s->close();
        _eventThread.join();
    }
    catch (exception const& e) {
        // the lock will unlock itself
    }
}

/***********/
void
Connection::launch_thread(bool daemon)
{
    // Launch a background thread to handle messages from the Tor
    // process.
    assert (_thread.get_id() == boost::thread::id());
    // boost/posix threads have no concept of being daemons or non-daemon
    _thread = boost::thread(boost::bind(&Connection::_loop, this));
    _eventThread = boost::thread(boost::bind(&Connection::_eventLoop, this));
}

/***********/
void
Connection::_loop()
{
    /*
    """Main subthread loop: Read commands from Tor, and handle them either
       as events or as responses to other commands.
    """
     */
    while (true) {
        bool isEvent;
        replyPtr reply;
        try {
            boost::tie(isEvent, reply) = _read_reply();
        }
        catch (TorCtlClosed& e) {
            LOGINFO("Tor closed control connection. Exiting event thread.");
            return;
        }
        catch (runtime_error& e) {
            if (!_closed) {
                LOGFATAL("exception shutdown");
                _err(e, false);
                return;
            }
            else {
                isEvent = false;
            }
        }
        
        if (isEvent) {
            if (_handler) {
                std::pair<ptime, replyPtr > eqi = std::make_pair(
                    microsec_clock::local_time(), reply);
                _eventQueue.put(eqi);
            }
        }
        else {
            CallbackContext* ctx = _queue.get();
            if (ctx == NULL) {
                // NULL queue item -> close
                _s.reset();
                LOGINFO("Event loop received close message.")
                return;
            }
            callit(true, reply.get(), *ctx);
        }
    }
}

/***********/
void
Connection::callit(bool success,
                reply_t* reply,
                CallbackContext& ctx)
{
    try {
        boost::lock_guard<boost::mutex> lock(ctx.mutex);
        ctx.success = success;
        if (success) {
            assert(reply);
            ctx.result.push_back(*reply);
        }
        ctx.condition.notify_one();
    }
    catch (exception const& e) {
        // nothing
    }
}

/***********/
void
Connection::_eventLoop()
{
    while (true) {
        ptime timestamp;
        replyPtr reply;
        boost::tie(timestamp, reply) = _eventQueue.get();
        if (reply == NULL) {
            LOGINFO("Event loop received close message.");
            return;
        }
        if (boost::tuples::get<0>((*reply)[0]) == "650" &&
            boost::tuples::get<1>((*reply)[0]) == "OK")
        {
            LOGDEBUG("Ignoring incompatible syntactic sugar: 650 OK");
            continue;
        }
        try {
            _handleFn(timestamp, *reply);
        }
        catch (runtime_error const& e) {
            LOGWARN("Error handling event: " << e.what()
                     << ". Exiting event loop.");
            _err(e, true);
            return;
        }
    }
}

void
Connection::_err(const std::runtime_error& ex,
                 const bool fromEventLoop)
{
    if (_s) {
        try {
            close();
        }
        catch (exception const& e) {
            // nothing
        }
    }
    _sendLock.lock();
    try {
        _closedEx.reset();
        _closedEx = make_shared<std::runtime_error>(ex);
        _closed = true;
    }
    catch (exception& e) {
        // nothing
    }
    _sendLock.unlock();
    while (true) {
        CallbackContext* ctx = NULL;
        bool timedout = _queue.get_with_timeout(time_duration::unit(), ctx);
        if (timedout) {
            break;
        }
        if (ctx != NULL) {
            // success=false will tell _sendImpl() to quit
            callit(false, NULL, *ctx);
        }
    }
    if (_closeHandler) {
        _closeHandler(make_shared<runtime_error>(ex));
    }
}

/***********/
Connection::reply_t
Connection::_sendImpl(const string& msg)
{
    if (_thread.get_id() == boost::thread::id() && !_closed) {
        this->launch_thread(true);
    }
    // This condition will get notified when we've got a result...
    boost::mutex m;
    boost::unique_lock<boost::mutex> lock(m, boost::defer_lock);
    boost::condition_variable condition;

    if (_closedEx) {
        throw *_closedEx;
    }
    else if (_closed) {
        throw TorCtlClosed();
    }

    // Sends a message to Tor...
    _sendLock.lock();
    // i wanna use "make_shared," but it requires "const &"
    CallbackContext ctx(m, condition);
    CallbackContext* ctxptr = &ctx;
    try {
        _queue.put(ctxptr);
        _doSend(msg);
    }
    catch (exception const& e) {
        // nothing
    }
    _sendLock.unlock();

    // Now wait till the answer is in...
    lock.lock();
    try {
        while (ctx.result.size() == 0) {
            condition.wait(lock);
        }
    }
    catch (exception const& e) {
        // nothing
    }
    lock.unlock();
    
    // ...And handle the answer appropriately.
    assert (ctx.result.size() == 1);
    if (!ctx.success) {
        throw *_closedEx;
    }
    return ctx.result[0];
}

/***********/
void
Connection::set_event_handler(EventHandler* handler)
{
    /*
    """Cause future events from the Tor process to be sent to 'handler'.
    """
     */
//    if (_handler.empty()) {
    _handler = handler;
    _handler->_c = this;
    _handleFn = boost::bind(&EventHandler::_handle1, handler, _1, _2);
}

/***********/
tuple<bool, shared_ptr<Connection::reply_t> >
Connection::_read_reply()
{
    replyPtr lines = make_shared<reply_t>();
    bool isEvent = false;
    while (true) {
        string line = _s->readline();
        if (line.empty()) {
            _closed = true;
            throw TorCtlClosed();
        }
        boost::trim(line);
        if (line.length() < 4) {
            throw ProtocolError("Badly formatted reply line: Too short");
        }
        string code = line.substr(0, 3);
        string tp = line.substr(3, 1);
        string s = line.substr(4);
        if (tp == "-") {
            lines->push_back(boost::make_tuple(code, s, ""));
        }
        else if (tp == " ") {
            lines->push_back(boost::make_tuple(code, s, ""));
            isEvent = (boost::get<0>((*lines)[0])[0] == '6');
            return boost::make_tuple(isEvent, lines);
        }
        else if (tp != "+") {
            throw ProtocolError(
                "Badly formatted reply line: unknown type " + tp);
        }
        else {
            vector<string> more;
            while (true) {
                line = _s->readline();
                if (line == ".\r\n" || line == ".\n" || line == "650 OK\n" ||
                    line == "650 OK\r\n")
                {
                    break;
                }
                more.push_back(line);
            }
            lines->push_back(boost::make_tuple(
                code, s, TorUtil::unescape_dots(boost::join(more, ""))));
            isEvent = (boost::get<0>((*lines)[0])[0] == '6');
            if (isEvent) {
                return boost::make_tuple(isEvent, lines);
            }
        }
    }
    
    // Not reached
    throw TorCtlError();
}

/***********/
void
Connection::_doSend(const string& msg)
{
    _s->write(msg);
}

/***********/
Connection::reply_t
Connection::sendAndRecv(const string& msg) throw (ErrorReply)
{
    /*
    """Helper: Send a command 'msg' to Tor, and wait for a command
       in response.  If the response type is in expectedTypes,
       return a list of (tp,body,extra) tuples.  If it is an
       error, raise ErrorReply.  Otherwise, raise ProtocolError.
    """
     */
    assert (boost::iends_with(msg, "\r\n"));

    reply_t lines;
    static const std::set<string> expectedTypes = boost::assign::list_of("250")("251");
    
    lines = _sendImpl(msg);
    string tp, msg2;
    BOOST_FOREACH(boost::tie(tp, msg2, boost::tuples::ignore), lines) {
        if (tp[0] == '4' || tp[0] == '5') {
            throw ErrorReply(tp + " " + msg2);
        }
        if (expectedTypes.find(tp) == expectedTypes.end()) {
            throw ProtocolError("Unexpectd message type " + tp);
        }
    }
    return lines;
}

/***********/
void
Connection::authenticate(const string& secret)
{
    // TODO: incomplete port
    sendAndRecv(string("AUTHENTICATE \"") + secret + "\"\r\n");
}

#if 0
/***********/
vector<std::pair<string, string> >
Connection::get_option(const std::string& name)
{
    reply_t lines = sendAndRecv(string("GETCONF ") + name + "\r\n");
    string& line;
    vector<std::pair<string, string> > r;
    BOOST_FOREACH(boost::tie(boost::tuples::ignore, line, boost::tuples::ignore),
                  lines)
    {
        try {
            size_t idx = line.find('=');
            r.push_back(std::make_pair(line.substr(0, idx+1), line.substr(idx+1)));
        }
        catch (exception const& e) {
        }
    }
}
#endif

/***********/
bool
Connection::is_alive()
{
    const time_duration unit = time_duration::unit();
    LOGDEBUG("_closed " << _closed << ", _thread id: " << _thread.get_id()
             << ", _eventThread id: " << _eventThread.get_id());
    return ! (_closed
              || _thread.timed_join(unit)
              || _eventThread.timed_join(unit));
}

/***********/
vector<NetworkStatusPtr >
Connection::get_consensus()
{
    /* verified matching pyctl as of revision 3695, indirectly from
     * parse_ns_body's verification.
     */
    return parse_ns_body(
        boost::tuples::get<2>(sendAndRecv("GETINFO dir/status-vote/current/consensus\r\n")[0]));
}

/***********/
vector<NetworkStatusPtr >
Connection::get_network_status(const string who)
{
    /* verified matching pyctl as of revision 3695, indirectly from
     * parse_ns_body's verification.
     */
    return parse_ns_body(
        boost::tuples::get<2>(sendAndRecv("GETINFO ns/"+who+"\r\n")[0]));
}

/***********/
RouterPtr
Connection::get_router(const NetworkStatus& ns)
{
    /*
    """Fill in a Router class corresponding to a given NS class"""
     */
    /* verified matching pyctl as of revision 3689. */
    string desc = boost::tuples::get<2>(
        sendAndRecv("GETINFO desc/id/" + ns._idhex + "\r\n")[0]);
    size_t sig_start = desc.find("\nrouter-signature\n") +
                        string("\nrouter-signature\n").length();
    unsigned char md[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)desc.substr(0, sig_start).c_str(),
         desc.substr(0, sig_start).length(), md);
    string fp_base64 = TorUtil::encode_base64(
        string((char*)&(md[0]), sizeof(md)));
    fp_base64 = fp_base64.substr(0, fp_base64.length() - 2);
    RouterPtr r = Router::build_from_desc(TorUtil::split(desc, "\n"), ns);
    if (fp_base64 != ns._orhash) {
        LOGINFO("Router descriptor for "<<ns._idhex
                <<" does not match ns fingerprint (NS @ "
                <<ns._updated << " vs Desc @ " << r->_published << ")");
        r.reset();
    }
    return r;
}

/***********/
vector<RouterPtr >
Connection::read_routers(const vector<NetworkStatusPtr >& nslist)
{
    /*
    """ Given a list a NetworkStatuses in 'nslist', this function will 
        return a list of new Router instances.
    """
     */
    /* verified matching pyctl as of revision 3689 (including the
     * exception path.
     */
    int bad_key = 0;
    vector<RouterPtr > newrouterlist;
    BOOST_FOREACH(const NetworkStatusPtr& ns, nslist) {
        try {
            RouterPtr r = get_router(*ns);
            if (r) {
                newrouterlist.push_back(r);
            }
        }
        catch (ErrorReply) {
            bad_key += 1;
            if (Common::inVector(ns->_flags, string("Running"))) {
                LOGNOTICE("Running router " << ns->_nickname << "=" <<
                          ns->_idhex << " has no descriptor");
            }
        }
    }
    return newrouterlist;
}

/***********/
void
Connection::set_events(const vector<string>& events, bool extended)
{
    /*
    """Change the list of events that the event handler is interested
       in to those in 'events', which is a list of event names.
       Recognized event names are listed in section 3.3 of the control-spec
    """
    */
    string msg;
    if (extended) {
        msg = ("SETEVENTS EXTENDED " + boost::join(events, " ") + "\r\n");
    }
    else {
        msg = ("SETEVENTS " + boost::join(events, " ") + "\r\n");
    }
    sendAndRecv(msg);
}

/***********/
uint64_t
Connection::extend_circuit(uint64_t circid, vector<string> hops)
{
    /*
    """Tell Tor to extend the circuit identified by 'circid' through the
       servers named in the list 'hops'.
    """
    */
    reply_t lines = sendAndRecv("EXTENDCIRCUIT " + lexical_cast<string>(circid)
                                + " " + boost::join(hops, ",") + "\r\n");

    string tp, msg;
    boost::tie(tp, msg, boost::tuples::ignore) = lines[0];
    boost::smatch m;
    static const regex e("EXTENDED (\\S*)");
    if (!regex_match(msg, m, e)) {
        throw ProtocolError("Bad extended line " + msg);
    }
    return lexical_cast<uint64_t>(m[1]);
}

/***********/
void
Connection::attach_stream(uint64_t streamid, uint64_t circid,
                          int hop)
{
    /*
    """Attach a stream to a circuit, specify both by IDs. If hop is given, 
       try to use the specified hop in the circuit as the exit node for 
       this stream.
    """
     */
    if (hop) {
        sendAndRecv("ATTACHSTREAM " + lexical_cast<string>(streamid) + " " +
            lexical_cast<string>(circid) + " HOP=" +
            lexical_cast<string>(hop) + "\r\n");
    }
    else {
        sendAndRecv("ATTACHSTREAM " + lexical_cast<string>(streamid) + " " +
            lexical_cast<string>(circid) + "\r\n");
    }
}

/***********/
void
Connection::close_stream(uint64_t streamid, uint8_t reason)
{
    sendAndRecv("CLOSESTREAM " + lexical_cast<string>(streamid) + " " +
                lexical_cast<string>(reason) + " \r\n");
}

/***********/
void
Connection::close_circuit(uint64_t circid, uint8_t reason)
{
    sendAndRecv("CLOSECIRCUIT " + lexical_cast<string>(circid) + " " +
                lexical_cast<string>(reason) + " \r\n");
}

/*******************************************************/
string
CircuitEvent::toString() const
{
    stringstream s;

#undef ADD_TO_S
#define ADD_TO_S(member)                                                \
    do {                                                                \
        s << (#member ": ") << (_##member) << "\n";                     \
    }                                                                   \
    while (0)

    ADD_TO_S(circ_id);
    ADD_TO_S(status);

    s << "path: " << boost::join(_path, ",") << "\n";

    ADD_TO_S(purpose);
    ADD_TO_S(reason);
    ADD_TO_S(remote_reason);

#undef ADD_TO_S

    return s.str();
}

/*******************************************************/
string
StreamEvent::toString(const bool succinct) const
{
    stringstream s;

#undef ADD_TO_S
#define ADD_TO_S(member)                                                \
    do {                                                                \
        s << (#member ": ") << (_##member) << "\n";                     \
    }                                                                   \
    while (0)

#undef ADD_TO_S_SUCCINCT
#define ADD_TO_S_SUCCINCT(label, member)                                \
    do {                                                                \
        s << label "=" << (_##member) << " ";                           \
    }                                                                   \
    while (0)

    if (succinct) {
        s << "strm_ev: ";
        ADD_TO_S_SUCCINCT("id", strm_id);
        ADD_TO_S_SUCCINCT("s", status);
        ADD_TO_S_SUCCINCT("ci", circ_id);
        ADD_TO_S_SUCCINCT("th", target_host);
        if (_reason.length()) {
            ADD_TO_S_SUCCINCT("r", reason);
        }
        if (_remote_reason.length()) {
            ADD_TO_S_SUCCINCT("rr", remote_reason);
        }
        if (_purpose.length()) {
            ADD_TO_S_SUCCINCT("p", purpose);
        }
    }
    else {
        ADD_TO_S(strm_id);
        ADD_TO_S(status);
        ADD_TO_S(circ_id);
        ADD_TO_S(target_host);
        ADD_TO_S(target_port);
        ADD_TO_S(reason);
        ADD_TO_S(remote_reason);
        ADD_TO_S(source);
        ADD_TO_S(source_addr);
        ADD_TO_S(purpose);
    }

#undef ADD_TO_S
#undef ADD_TO_S_SUCCINCT

    return s.str();
}

/*******************************************************/
void
EventHandler::_handle1(ptime timestamp, const Connection::reply_t& lines)
{
    /*
    """Dispatcher: called from Connection when an event is received."""
     */
    string code, msg, data;
#if 0
    BOOST_FOREACH(boost::tie(code, msg, data), lines) {
#else
    for (size_t i = 0; i < lines.size(); ++i) {
        const TorCtl::Connection::reply_line_t& rl = lines[i];
        code = boost::get<0>(rl);
        msg = boost::get<1>(rl);
        data = boost::get<2>(rl);
#endif
        EventPtr event = _decode1(msg, data);
//        event->_arrived_at = microsec_clock::local_time();
        event->_arrived_at = timestamp;
        event->_state = EVENT_STATE::PRELISTEN;
//         for l in self.pre_listeners:
//             l.listen(event)
        event->_state = EVENT_STATE::HEARTBEAT;
//         _heartbeat_event(event);
        event->_state = EVENT_STATE::HANDLING;

        if (event->_event_name == "CIRC") {
            circ_status_event(event.get());
        }
        else if (event->_event_name == "STREAM") {
            stream_status_event(event.get());
        }
        else if (event->_event_name == "ORCONN") {
            or_conn_status_event(event.get());
        }
        else if (event->_event_name == "STREAM_BW") {
            stream_bw_event(event.get());
        }
        else if (event->_event_name == "BW") {
            bandwidth_event(event.get());
        }
        else if (event->_event_name == "DEBUG" ||
                 event->_event_name == "INFO" ||
                 event->_event_name == "NOTICE" ||
                 event->_event_name == "WARN" ||
                 event->_event_name == "ERR")
        {
            msg_event(event.get());
        }
        else if (event->_event_name == "NEWDESC") {
            new_desc_event(event.get());
        }
        else if (event->_event_name == "ADDRMAP") {
            address_mapped_event(event.get());
        }
        else if (event->_event_name == "NS") {
            ns_event(event.get());
        }
        else if (event->_event_name == "NEWCONSENSUS") {
            new_consensus_event(event.get());
        }
        else if (event->_event_name == "BUILDTIMEOUT_SET") {
            buildtimeout_set_event(event.get());
        }
        else if (event->_event_name == "GUARD") {
            guard_event(event.get());
        }
        else if (event->_event_name == "TORCTL_TIMER") {
            timer_event(event.get());
        }

        event->_state = EVENT_STATE::POSTLISTEN;
//         for l in self.post_listeners:
//             l.listen(event)
    }
}

/****************/
EventPtr
EventHandler::_decode1(const string& body_, const string& data)
{
    /*
    """Unpack an event message into a type/arguments-tuple tuple."""
     */
    string evtype, body;
    static const set<string> logEvents =
        boost::assign::list_of("DEBUG")("INFO")("NOTICE")("WARN")("ERR");

    if (body_.find(' ') != string::npos) {
        vector<string> parts = TorUtil::split(body_, " ", 1);
        evtype = parts[0];
        body = parts[1];
    }
    else {
        evtype = body_;
        body = "";
    }
    boost::algorithm::to_upper(evtype);
    if (evtype == "CIRC") {
        static const regex e(
            "(\\d+)\\s+(\\S+)(\\s\\S+)?(\\s\\S+)?(\\s\\S+)?(\\s\\S+)?");
        boost::smatch m;
        if (!regex_match(body, m, e)) {
            throw ProtocolError("CIRC event misformatted.");
        }
        vector<string> pathVec;
        string ident,status,path,purpose,reason,remote;
        string* array[] = {
            NULL, &ident, &status, &path, &purpose, &reason, &remote};
        for (size_t i = 1; i < m.size(); ++i) {
            *array[i] = m[i];
        }
        if (!path.empty()) {
            if (path.find("PURPOSE=") != string::npos) {
                remote = reason;
                reason = purpose;
                purpose = path;
            }
            else if (path.find("REASON=") != string::npos) {
                remote = reason;
                reason = path;
                purpose = "";
            }
            else {
                path = boost::trim_copy(path);
                vector<string> path_verb = TorUtil::split(path, ",");
                for (vector<string>::iterator it = path_verb.begin();
                     it != path_verb.end(); ++it) {
                    pathVec.push_back(TorUtil::split(
                        boost::replace_all_copy(*it, "~", "="), ",")[0]);
                }
            }
        }
        else {
            // nothing
        }
        
        if (!purpose.empty() && (purpose.find("REASON=") != string::npos)) {
            remote = reason;
            reason = purpose;
            purpose = "";
        }
        
        if (!purpose.empty()) {
            purpose = purpose.substr(9);
        }
        if (!reason.empty()) {
            reason = reason.substr(8);
        }
        if (!remote.empty()) {
            remote = remote.substr(15);
        }

        return make_shared<CircuitEvent>(
            evtype, lexical_cast<uint64_t>(ident),
            status, pathVec, purpose, reason, remote);
    }
    else if (evtype == "STREAM") {
        static const regex e(
            "(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)?:(\\d+)(\\sREASON=\\S+)?(\\sREMOTE_REASON=\\S+)?(\\sSOURCE=\\S+)?(\\sSOURCE_ADDR=\\S+)?(\\s+PURPOSE=\\S+)?");
        boost::smatch m;
        if (!regex_match(body, m, e)) {
            throw ProtocolError("STREAM event misformatted.");
        }
        string ident,status,circ,target_host,target_port,reason,remote,source,source_addr,purpose;
        string* array[] = {
            NULL,&ident,&status,&circ,&target_host,&target_port,&reason,&remote,&source,&source_addr,&purpose};
        for (size_t i = 1; i < m.size(); ++i) {
            *array[i] = m[i];
        }
        if (target_host.empty()) {
            target_host = "(none)";
        }
        if (!reason.empty()) {
            reason = reason.substr(8);
        }
        if (!remote.empty()) {
            remote = remote.substr(15);
        }
        if (!source.empty()) {
            source = source.substr(8);
        }
        if (!source_addr.empty()) {
            source_addr = source_addr.substr(13);
        }
        if (!purpose.empty()) {
            purpose = boost::trim_left_copy(purpose);
            purpose = purpose.substr(8);
        }
        // "make_shared" complains
        return shared_ptr<StreamEvent>(
            new StreamEvent(evtype, lexical_cast<uint64_t>(ident),
                            status, lexical_cast<uint64_t>(circ),
                            target_host, lexical_cast<int>(target_port),
                            reason, remote, source, source_addr, purpose));
    }
    else if (evtype == "OR_CONN") {
        static const regex e(
            "(\\S+)\\s+(\\S+)(\\sAGE=\\S+)?(\\sREAD=\\S+)?(\\sWRITTEN=\\S+)?(\\sREASON=\\S+)?(\\sNCIRCS=\\S+)");
        boost::smatch m;
        if (!regex_match(body, m, e)) {
            throw ProtocolError("ORCONN event misformatted.");
        }
        string target, status, age, read, wrote, reason, ncircs;
        string* array[] = {
            NULL, &target, &status, &age, &read, &wrote, &reason, &ncircs};
        for (size_t i = 1; i < m.size(); ++i) {
            *array[i] = m[i];
        }
        if (!ncircs.empty()) {
            ncircs = ncircs.substr(8);
        }
        else {
            ncircs = "0";
        }
        if (!reason.empty()) {
            reason = reason.substr(8);
        }
        if (!age.empty()) {
            age = age.substr(5);
        }
        else {
            age = "0";
        }
        if (!read.empty()) {
            read = read.substr(6);
        }
        else {
            read = "0";
        }
        if (!wrote.empty()) {
            wrote = wrote.substr(9);
        }
        else {
            wrote = "0";
        }
        return make_shared<ORConnEvent>(evtype, status, target,
                                        lexical_cast<int>(age),
                                        lexical_cast<int>(read),
                                        lexical_cast<int>(wrote),
                                        reason, lexical_cast<int>(ncircs));
    }
    else if (evtype == "STREAM_BW") {
        static const regex e(
            "(\\d+)\\s+(\\d+)\\s+(\\d+)");
        boost::smatch m;
        if (!regex_match(body, m, e)) {
            throw ProtocolError("STREAM_BW event misformatted.");
        }
        string strm_id, written, read;
        string* array[] = {
            NULL, &strm_id, &written, &read};
        for (size_t i = 1; i < m.size(); ++i) {
            *array[i] = m[i];
        }
        return make_shared<StreamBwEvent>(evtype,
                                          lexical_cast<uint64_t>(strm_id),
                                          lexical_cast<unsigned long>(written),
                                          lexical_cast<unsigned long>(read));
    }
    else if (evtype == "BW") {
        // TODO: implement
        THROW_NYH();
    }
    else if (logEvents.end() != logEvents.find(evtype)) {
        // TODO: implement
        THROW_NYH();
    }
    else if (evtype == "NEWDESC" ) {
        vector<string> ids_verb = TorUtil::split(body, " ");
        vector<string> ids;
        for (vector<string>::iterator it = ids_verb.begin(); it != ids_verb.end(); ++it) {
            ids.push_back(
                boost::replace_all_copy(
                    TorUtil::split(
                        boost::replace_all_copy(*it, "~", "="),
                        "=")[0],
                    "$", "")
                );
        }

        return make_shared<NewDescEvent>(evtype, ids);
    }
    else if (evtype == "NS" ) {
        return make_shared<NetworkStatusEvent>(evtype, parse_ns_body(data));
    }
    else if (evtype == "NEWCONSENSUS" ) {
        return make_shared<NewConsensusEvent>(evtype, parse_ns_body(data));
    }
    // not reached
    throw runtime_error("should not reach");
}

/*******************************************************/
ConsensusTracker::ConsensusTracker(Connection* c, bool consensus_only)
    : _consensus_count(0), _consensus_only(consensus_only)
{
    _sorted_r = make_shared<vector<RouterPtr> >();
    c->set_event_handler(this);
    update_consensus();
}

/****************/
void
ConsensusTracker::_read_routers(const vector<NetworkStatusPtr >& nslist)
{
    /*
    # Routers can fall out of our consensus five different ways:
    # 1. Their descriptors disappear
    # 2. Their NS documents disappear
    # 3. They lose the Running flag
    # 4. They list a bandwidth of 0
    # 5. They have 'opt hibernating' set
     */
    vector<RouterPtr > routers = _c->read_routers(nslist);
    _consensus_count = routers.size();
    set<string> old_idhexes;
    for (map<string, RouterPtr >::iterator it = _routers.begin();
         it != _routers.end(); ++it)
    {
        old_idhexes.insert(it->first);
    }

    set<string> new_idhexes;
    for (vector<RouterPtr >::iterator it = routers.begin();
         it != routers.end(); ++it)
    {
        new_idhexes.insert((*it)->_idhex);
    }

    BOOST_FOREACH(const RouterPtr& r, routers) {
        if (Common::inMap(_routers, r->_idhex)) {
            if (_routers[r->_idhex]->_nickname != r->_nickname) {
                LOGNOTICE("Router "<<r->_idhex<<" changed names from "
                          <<_routers[r->_idhex]->_nickname<<" to "
                          <<r->_nickname);
                THROW_NYH();
            }
            // Must do IN-PLACE update to keep all the refs to this router
            // valid and current
            _routers[r->_idhex]->update_to(*r);
        }
        else {
            RouterPtr rc(new Router(*r));
            _routers[rc->_idhex] = rc;
        }
    }

    //////////
    set<string> removed_idhexes;
    for (set<string>::iterator it = old_idhexes.begin();
         it != old_idhexes.end(); ++it)
    {
        if (old_idhexes.end() == old_idhexes.find(*it)) {
            removed_idhexes.insert(*it);
        }
    }
    for (vector<RouterPtr >::const_iterator it = routers.begin();
         it != routers.end(); ++it)
    {
        if ((*it)->_down) {
            removed_idhexes.insert((*it)->_idhex);
        }
    }

    ////////////
    BOOST_FOREACH(const string& i, removed_idhexes) {
        if (!Common::inMap(_routers, i)) {
            continue;
        }
        _routers[i]->_down = true;
        // use remove_if?
        vector<string>::iterator loc = std::find(_routers[i]->_flags.begin(),
                                                 _routers[i]->_flags.end(),
                                                 "Running");
        if (loc != _routers[i]->_flags.end()) {
            _routers[i]->_flags.erase(loc);
        }
        if (_routers[i]->_refcount == 0) {
            _routers[i]->_deleted = true;
            _routers[i].reset();
            LOGINFO("Expiring non-running router "<<i);
            _routers.erase(i);
        }
        else {
            LOGINFO("Postponing expiring non-running router "<<i);
            _routers[i]->_deleted = true;
        }
    }
    
    __update_sorted_r();

    _sanity_check(_sorted_r);
}

/****************/
void
ConsensusTracker::_sanity_check(RouterPtrVecPtr list)
{
    if ( _routers.size() > (1.5 * _consensus_count)) {
        assert (false);
        LOGWARN("Router count of " << _routers.size() <<
                " exceeds consensus count " << _consensus_count <<
                " by more than 50%");
    }
    BOOST_FOREACH(const RouterPtr& r, (*list)) {
        if (r->_down) {
            LOGWARN("Router "<<r->_idhex<<" still present but is down. Del: "
                    <<r->_deleted<<", flags: "<<boost::join(r->_flags, " ")
                    <<", bw: "<<r->_bw);
        }

        if (r->_deleted) {
            LOGWARN("Router " << r->_idhex <<
                    " still present but is deleted. Down: " << r->_down <<
                    ", flags: "<<boost::join(r->_flags, " ") <<
                    ", bw: " << r->_bw);
        }

    }

    return;
}

/****************/
void
ConsensusTracker::_update_consensus(const vector<NetworkStatusPtr >& nslist)
{
    _ns_map.clear();
    BOOST_FOREACH(const NetworkStatusPtr& n, nslist) {
        _ns_map.insert(std::make_pair(n->_idhex, n));
        _name_to_key.insert(std::make_pair(n->_nickname, "$" + n->_idhex));
    }
}

/****************/
void
ConsensusTracker::update_consensus()
{
    if (_consensus_only) {
        _update_consensus(_c->get_consensus());
    }
    else {
        _update_consensus(_c->get_network_status());
    }

    vector<NetworkStatusPtr > nslist;
    for (map<string, NetworkStatusPtr >::iterator it = _ns_map.begin();
         it != _ns_map.end(); ++it)
    {
        nslist.push_back((*it).second);
    }
    _read_routers(nslist);
}

/****************/
void
ConsensusTracker::new_consensus_event(const Event* _n)
{
    const NetworkStatusEvent& n =
        *(dynamic_cast<const NetworkStatusEvent*>(_n));
    _update_consensus(n._nslist);

    vector<NetworkStatusPtr > nslist;
    for (map<string, NetworkStatusPtr >::iterator it = _ns_map.begin();
         it != _ns_map.end(); ++it)
    {
        nslist.push_back((*it).second);
    }
    _read_routers(nslist);
}

/****************/
bool
ConsensusTracker::new_desc_event(const Event* _d)
{
    const NewDescEvent& d = *(dynamic_cast<const NewDescEvent*>(_d));
    bool update = false;
    BOOST_FOREACH(const string& i, d._idlist) {
        vector<NetworkStatusPtr > nslist;
        vector<RouterPtr > routers;
        try {
            if (Common::inMap(_ns_map, i)) {
                nslist.push_back(_ns_map[i]);
            }
            else {
                LOGWARN("Need to getinfo ns/id for router desc: " << i);
                nslist = _c->get_network_status("id/"+i);
            }
            routers = _c->read_routers(nslist);
        }
        catch (ErrorReply const& e) {
            LOGWARN("Error reply for " << i << " after NEWDESC: "
                   << e.what());
            continue;
        }
        if (routers.size() == 0) {
            LOGWARN("No router desc for " << i << " after NEWDESC");
            continue;
        }
        else if (routers.size() != 1) {
            LOGWARN("Multiple descs for " << i << " after NEWDESC");
        }
        RouterPtr r = routers[0];
        NetworkStatus& ns = *(nslist[0]);
        if (Common::inMap(_routers, ns._idhex)
            && _routers[ns._idhex]->_orhash == r->_orhash)
        {
            LOGNOTICE("Got extra NEWDESC event for router " << ns._nickname
                      << "=" << ns._idhex);
        }
        else {
            _consensus_count += 1;
        }
        _name_to_key[ns._nickname] = "$" + ns._idhex;
        if (r && Common::inMap(_ns_map, r->_idhex)) {
            if (ns._orhash != _ns_map[r->_idhex]->_orhash) {
                LOGWARN("Getinfo and consensus disagree for "<< r->_idhex);
                continue;
            }
            update = true;
            if (Common::inMap(_routers, r->_idhex)) {
                _routers[r->_idhex]->update_to(*r);
            }
            else {
                _routers[r->_idhex] = make_shared<Router>(*r);
            }
        }
    }
    
    if (update) {
        __update_sorted_r();
    }

    _sanity_check(_sorted_r);
    return update;
}

/****************/
bool
ConsensusTracker::ns_event(const Event* _ev)
{
    const NetworkStatusEvent& ev =
        *(dynamic_cast<const NetworkStatusEvent*>(_ev));
    bool update = false;
    BOOST_FOREACH(const NetworkStatusPtr& _ns, ev._nslist) {
        const NetworkStatus& ns = *_ns;
        // Check current consensus.. If present, check flags
        if (Common::inMap(_ns_map, ns._idhex)
            && Common::inMap(_routers, ns._idhex)
            && ns._orhash == _ns_map[ns._idhex]->_orhash)
        {
            if (Common::inVector(ns._flags, string("Running"))
                && !Common::inVector(_ns_map[ns._idhex]->_flags,
                                     string("Running")))
            {
                LOGINFO("Router " << ns._nickname << "=" <<
                        ns._idhex <<" is now up.");
                update = true;
                _routers[ns._idhex]->_flags = ns._flags;
                _routers[ns._idhex]->_down = false;
            }

            if (!Common::inVector(ns._flags, string("Running"))
                && Common::inVector(_ns_map[ns._idhex]->_flags,
                                    string("Running")))
            {
                LOGINFO("Router " << ns._nickname << "=" <<
                        ns._idhex << " is now down.");
                update = true;
                _routers[ns._idhex]->_flags = ns._flags;
                _routers[ns._idhex]->_down = true;
            }
        }
    }

    if (update) {
        __update_sorted_r();
    }

    _sanity_check(_sorted_r);
    return update;
}

/****************/
ConsensusPtr
ConsensusTracker::current_consensus()
{
    return make_shared<Consensus>(
        _ns_map, _sorted_r, _routers, _name_to_key,
        _consensus_count);
}

/****************/
void
ConsensusTracker::__update_sorted_r()
{
    (*_sorted_r).clear();
    for (map<string, RouterPtr >::const_iterator it = _routers.begin();
         it != _routers.end(); ++it)
    {
        const Router& r = *(it->second);
        if (!r._down) {
            (*_sorted_r).push_back(it->second);
        }
    }
    // sort in descending order of bw
    std::sort((*_sorted_r).begin(), (*_sorted_r).end(),
              boost::bind(&Router::_bw, _1) > boost::bind(&Router::_bw, _2));

    for (size_t i = 0; i < (*_sorted_r).size(); ++i) {
        (*_sorted_r)[i]->_list_rank = i;
    }
}

/*******************************************************/
RouterVersion::RouterVersion(const string& version)
{
    if (!version.empty()) {
        boost::smatch m;
        static const regex e("^(\\d+).(\\d+).(\\d+).(\\d+)");
        assert(regex_search(version, m, e));
        // the subgroups start at index 1.
        _version = lexical_cast<int>(m[1])*0x1000000 +
                   lexical_cast<int>(m[2])*0x10000 +
                   lexical_cast<int>(m[3])*0x100 +
                   lexical_cast<int>(m[4]);
        _ver_string = version;
        _valid = true;
    }
    else {
        THROW_NYH(); // need to check this
        // _version = version;
        _ver_string = "unknown";
    }
}

string
ExitPolicyLine::toString() const
{
    stringstream s;
    if (_match) {
        s << "accept ";
    }
    else {
        s << "reject ";
    }

    char buf[INET_ADDRSTRLEN + 1] = {0};
    const uint32_t ip = htonl(_ip);
    assert (buf == inet_ntop(AF_INET, &ip, buf, sizeof buf));
    s << buf;
    s << "/";

    memset(buf, 0, sizeof buf);
    const uint32_t netmask = htonl(_netmask);
    assert (buf == inet_ntop(AF_INET, &netmask, buf, sizeof buf));
    s << buf;
    s << ":";

    s << (_port_low) << "-" << (_port_high);

    s << (" (raw int: ") << (_ip) << "/" << (_netmask) << ")";
    return s.str();
}

ExitPolicyLine::ExitPolicyLine(bool match, string ip_mask,
                               string port_low, string port_high)
{
    /* verified matching pyctl as of revision 3689, except for some
     * code paths that even python code doesn't reach yet.
     */
    _match = match;
    if (ip_mask == "*") {
        _ip = 0;
        _netmask = 0;
    }
    else {
        string ip;
        if (ip_mask.find("/") == string::npos) {
            _netmask = 0xFFFFFFFF;
            ip = ip_mask;
        }
        else {
            ip = TorUtil::split(ip_mask, "/")[0];
            const string mask = TorUtil::split(ip_mask, "/")[1];
            // tested
            static const regex ipaddress_re("(\\d{1,3}\\.){3}\\d{1,3}$");
            if (regex_search(mask, ipaddress_re)) {
                THROW_NYH();
                assert (1 == inet_pton(AF_INET, mask.c_str(), &_netmask));
            }
            else {
                _netmask = 0xffffffff ^ (0xffffffff >> lexical_cast<int>(mask));
            }
        }
        assert (1 == inet_pton(AF_INET, ip.c_str(), &_ip));
        _ip = ntohl(_ip);
    }
    _ip &= _netmask;
    if (port_low == "*") {
        _port_low = 0;
        _port_high = 65535;
    }
    else {
        if (port_high.empty()) {
            port_high = port_low;
        }
        _port_low = lexical_cast<uint16_t>(port_low);
        _port_high = lexical_cast<uint16_t>(port_high);
    }
}

bool
ExitPolicyLine::check(const string& ip, const uint16_t port, bool& accept) const
{
    uint32_t ipint = 0;
    assert (1 == inet_pton(AF_INET, ip.c_str(), &ipint));
    ipint = ntohl(ipint);
    if ((ipint & _netmask) == _ip) {
        if (_port_low <= port && port <= _port_high) {
            accept = _match;
            return true;
        }
    }
    return false;
}

Router::Router(const string& idhex, const string& name, int bw, bool down,
               const vector<ExitPolicyLine>& exitpolicy, const vector<string>& flags,
               const string& ip, const string& version, const string& os, seconds uptime,
               ptime published, const string& contact, bool rate_limited,
               const string& orhash, int ns_bandwidth,
               const string& extra_info_digest)
    : _idhex(idhex), _nickname(name), _desc_bw(bw), _exitpolicy(exitpolicy),
      _flags(flags), _down(down), _version(RouterVersion(version)), _os(os),
      _list_rank(0), _uptime(uptime), _published(published), _refcount(0),
      _deleted(false), _contact(contact), _rate_limited(rate_limited),
      _orhash(orhash), _extra_info_digest(extra_info_digest)
{
    /* verified matching pyctl as of revision 3689. */
    if (ns_bandwidth != -1) {
        _bw = ns_bandwidth;
    }
    else {
        _bw = bw;
    }
    assert (1 == inet_pton(AF_INET, ip.c_str(), &_ip));
    _ip = ntohl(_ip);
}

RouterPtr
Router::build_from_desc(const vector<string>& desc,
                        const NetworkStatus& ns)
{
    /* verified matching pyctl as of revision 3689. */
    vector<ExitPolicyLine> exitpolicy;
    bool dead = !Common::inVector(ns._flags, string("Running"));
    int bw_observed = 0;
    string version;
    string os;
    seconds uptime(not_a_date_time);
    string ip;
    string router = "[none]";
    ptime published;
    string contact;
    bool rate_limited;
    string extra_info_digest;

    static const map<string, regex> desc_re =
        boost::assign::map_list_of
        ("router", regex("(\\S+) (\\S+)"))
        ("opt fingerprint", regex("(.+).*on (\\S+)")) /* XXX/this
                                                       * regex looks
                                                       * wrong*/
        ("opt extra-info-digest", regex("(\\S+)"))
        ("opt hibernating", regex("1$"))
        ("platform", regex("Tor (\\S+).*on ([\\S\\s]+)"))
        ("accept", regex("(\\S+):([^-]+)(?:-(\\d+))?"))
        ("reject", regex("(\\S+):([^-]+)(?:-(\\d+))?"))
        ("bandwidth", regex("(\\d+) \\d+ (\\d+)"))
        ("uptime", regex("(\\d+)"))
        ("contact", regex("(.+)"))
        ("published", regex("(\\S+ \\S+)"))
        ;

    BOOST_FOREACH(const string& line, desc) {
        vector<string> parts = TorUtil::split(line, " ", 1);
        string kw = parts[0];
        string rest = parts.size() > 1 ? parts[1] : "";

        if (kw == "opt") {
            parts = TorUtil::split(rest, " ", 1);
            kw += " " + parts[0];
            // be careful here. if parts had >= 2 elements, and this
            // 2nd split call returns a vector with only 1 element,
            // then the original parts[1] remains, even if
            // parts.clear() was called before this second split!
            rest = parts.size() > 1 ? parts[1] : "";
        }

        if (!Common::inMap(desc_re, kw)) {
            // if we don't handle this keyword, just move on to the
            // next one.
            continue;
        }

        boost::smatch m;
        if (!regex_search(rest, m, Common::getFromMap(desc_re, kw))) {
            // if we do handle this keyword but its data is malformed,
            // move on to the next one without processing it.
            continue;
        }

        if (kw == "accept") {
            exitpolicy.push_back((ExitPolicyLine(true, m[1], m[2], m[3])));
        }
        else if (kw == "reject") {
            exitpolicy.push_back((ExitPolicyLine(false, m[1], m[2], m[3])));
        }
        else if (kw == "router") {
            router = m[1];
            ip = m[2];
        }
        else if (kw == "bandwidth") {
            vector<int> bws = boost::assign::list_of(lexical_cast<int>(m[1]))
                                                    (lexical_cast<int>(m[2]));
            bw_observed = *std::min_element(bws.begin(), bws.end());
            rate_limited = false;
            if (bws[0] < bws[1]) {
                rate_limited = true;
            }
        }
        else if (kw == "platform") {
            version = m[1];
            os = m[2];
        }
        else if (kw == "uptime") {
            uptime = seconds(lexical_cast<long>(m[1]));
        }
        else if (kw == "published") {
            // m[1] should be like this "2010-12-24 12:48:17"
            struct tm tm;
            assert (NULL != strptime(
                        (m[1]+" UTC").c_str(), "20%y-%m-%d %H:%M:%S %Z", &tm));
            published = ptime_from_tm(tm);
        }
        else if (kw == "contact") {
            contact = m[1];
        }
        else if (kw == "opt extra-info-digest") {
            extra_info_digest = m[1];
        }
        else if (kw == "opt hibernating") {
            dead = true;
            if (Common::inVector(ns._flags, string("Running"))) {
                LOGINFO("Hibernating router "<<ns._nickname
                        <<" is running, flags: "<<boost::join(ns._flags, " "));
            }
        }
    }
    
    if (router != ns._nickname) {
        LOGINFO("Got different names " << ns._nickname << " vs "
                << router << " for " << ns._idhex);
    }
    if (!bw_observed && !dead && Common::inVector(ns._flags, string("Valid")))
    {
        LOGINFO("No bandwidth for live router "<<ns._nickname<<", flags: "
                <<boost::join(ns._flags, " "));
        dead = true;
    }
    if (version.empty() || os.empty()) {
        LOGINFO("No version and/or OS for router " <<ns._nickname);
    }
    return RouterPtr(
        new Router(ns._idhex, ns._nickname, bw_observed, dead, exitpolicy,
                   ns._flags, ip, version, os, uptime, published, contact,
                   rate_limited, ns._orhash, ns._bandwidth, extra_info_digest));
}

void
Router::update_to(const Router& r)
{
    if (_idhex != r._idhex) {
        LOGERROR("Update of router "<<_nickname<<" changes idhex!");
        THROW_NYH();
    }

#define _UPDATE(member) member = r.member

    // do not update _refcount and _generated

    _UPDATE(_idhex);
    _UPDATE(_nickname);
    _UPDATE(_bw);
    _UPDATE(_desc_bw);
    _UPDATE(_exitpolicy);
    _UPDATE(_flags);
    _UPDATE(_down);
    _UPDATE(_ip);
    _UPDATE(_version);
    _UPDATE(_os);
    _UPDATE(_list_rank);
    _UPDATE(_uptime);
    _UPDATE(_published);
    _UPDATE(_deleted);
    _UPDATE(_contact);
    _UPDATE(_rate_limited);
    _UPDATE(_orhash);

#undef _UPDATE

    return;
}

bool
Router::will_exit_to(const string& ip, uint16_t port) const
{
    BOOST_FOREACH(const ExitPolicyLine& line, _exitpolicy) {
        bool accept = false;
        bool matchedLine = line.check(ip, port, accept);
        if (matchedLine) {
            return accept;
        }
    }
    return false;
}

string
Router::toString() const
{
    stringstream s;

#undef ADD_TO_S
#define ADD_TO_S(member)                                                \
    do {                                                                \
        s << (#member ": ") << (_##member) << "\n";                     \
    }                                                                   \
    while (0)

    ADD_TO_S(idhex);
    ADD_TO_S(nickname);
    ADD_TO_S(bw);
    ADD_TO_S(desc_bw);

    s << "flags: " << boost::join(_flags, ",") << "\n";

    ADD_TO_S(down);

    char buf[INET_ADDRSTRLEN] = {0};
    uint32_t ip = htonl(_ip);
    assert (buf == inet_ntop(AF_INET, &ip, buf, sizeof buf));
    s << ("ip: ") << buf;
    s << (" (raw int: ") << (_ip) << ")\n";

    s << ("version: ") << (_version._version)
      << ", " << _version._ver_string << "\n";

    ADD_TO_S(os);
    ADD_TO_S(list_rank);

    s << "uptime: " << (_uptime) << "\n";
    s << "published: " << (_published) << "\n";

    ADD_TO_S(refcount);
    ADD_TO_S(deleted);
    ADD_TO_S(contact);
    ADD_TO_S(rate_limited);
    ADD_TO_S(orhash);
    ADD_TO_S(extra_info_digest);

    s << "exit policies:\n";
    BOOST_FOREACH(const ExitPolicyLine& epl, _exitpolicy) {
        s << ("  ") << epl.toString() << "\n";
    }

#undef ADD_TO_S

    return s.str();
}
