
#ifndef TORCTL_HPP
#define TORCTL_HPP

/* $Id$ */

#include <boost/thread/recursive_mutex.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/function.hpp>
#include <boost/make_shared.hpp>
#include <assert.h>

#include "TorUtil.hpp"
#include "ThreadSafeQueue.hpp"
#include "common.hpp"

#include "Log.hpp"

using namespace boost::asio::ip;
using namespace boost::posix_time;
using boost::tuple;
using boost::shared_ptr;
using std::map;
using std::runtime_error;
using std::exception;

#define ARRAY_LENGTH(array) (sizeof(array)/sizeof((array)[0]))

namespace TorCtl {

/* copied from Tor's or.h file */
#define END_STREAM_REASON_MISC 1
#define END_STREAM_REASON_RESOLVEFAILED 2
#define END_STREAM_REASON_CONNECTREFUSED 3
#define END_STREAM_REASON_EXITPOLICY 4
#define END_STREAM_REASON_DESTROY 5
#define END_STREAM_REASON_DONE 6
#define END_STREAM_REASON_TIMEOUT 7
#define END_STREAM_REASON_NOROUTE 8
#define END_STREAM_REASON_HIBERNATING 9
#define END_STREAM_REASON_INTERNAL 10
#define END_STREAM_REASON_RESOURCELIMIT 11
#define END_STREAM_REASON_CONNRESET 12
#define END_STREAM_REASON_TORPROTOCOL 13
#define END_STREAM_REASON_NOTDIRECTORY 14
#define END_STREAM_REASON_ENTRYPOLICY 15

    class TorCtlError : public runtime_error {
    public:
        TorCtlError() : runtime_error("<none specified>") {};
        explicit TorCtlError(const string& s) : runtime_error(s) {};
    };
    class TorCtlClosed : public TorCtlError {};
    class ProtocolError : public TorCtlError {
    public:
        explicit ProtocolError(const string& s) : TorCtlError(s) {};
    };
    class ErrorReply : public TorCtlError {
    public:
        explicit ErrorReply(const string& s) : TorCtlError(s) {};
    };
    class EventHandler;
    class Router;
    typedef shared_ptr<Router> RouterPtr;
    typedef shared_ptr<vector<RouterPtr> > RouterPtrVecPtr;
    class NetworkStatus;
    typedef shared_ptr<NetworkStatus> NetworkStatusPtr;

    class Connection {
    public:
        Connection(tcp::socket& sock);
        void close();
        void authenticate(const string& secret="");
        void set_event_handler(EventHandler* handler);
        void get_option(const string& name);

        void set_close_handler(void(*closeHandler)(shared_ptr<runtime_error> exc))
        {
            _closeHandler = closeHandler;
        }
        /* should not call from the _loop or _eventLoop threads.
         *
         * Returns true iff the connection is alive and healthy
         */
        bool is_alive();

        void set_events(const vector<string>& events, bool extended=false);
        RouterPtr get_router(const NetworkStatus& ns);
        vector<RouterPtr > read_routers(const vector<NetworkStatusPtr >& nslist);
        vector<NetworkStatusPtr > get_consensus();
        vector<NetworkStatusPtr > get_network_status(const string who="all");
        uint64_t extend_circuit(uint64_t circid, vector<string> hops);
        void attach_stream(uint64_t streamid, uint64_t circid, int hop=0);
        void close_stream(uint64_t streamid, uint8_t reason=0);
        void close_circuit(uint64_t circid, uint8_t reason=0);

        virtual void dummy() {}; // so can use dynamic_cast

    typedef tuple<string, string, string> reply_line_t;
    typedef vector<reply_line_t> reply_t;
    typedef shared_ptr<reply_t> replyPtr;
    private:
        void launch_thread(bool daemon=true);
        void _loop();
        void _eventLoop();
        reply_t _sendImpl(const string& msg); // to keep it simple, not using the sendFn here
        tuple<bool, replyPtr > _read_reply();
        void _doSend(const string& msg);
        reply_t sendAndRecv(const string& msg="") throw (ErrorReply);
        void _err(const std::runtime_error& e,
                  const bool fromEventLoop);

        class CallbackContext {
        public:
            CallbackContext(boost::mutex& mutex_,
                            boost::condition_variable& condition_) :
                            mutex(mutex_), condition(condition_), success(false) {};
            boost::mutex& mutex;
            boost::condition_variable& condition;
            bool success;
            vector<reply_t> result;
        };

        static void callit(bool success,
                reply_t* reply,
                CallbackContext& ctx);

        static log4cxx::LoggerPtr _logger;

        EventHandler* _handler;
        boost::function<void (ptime timestamp, reply_t& lines)> _handleFn;
        boost::recursive_mutex _sendLock;
        ThreadSafeQueue<CallbackContext* > _queue;
        boost::thread _thread;
        shared_ptr<std::runtime_error> _closedEx;
        bool _closed;
        void (*_closeHandler)(shared_ptr<runtime_error> exc);
        boost::thread _eventThread;
        ThreadSafeQueue<std::pair<ptime, replyPtr > > _eventQueue;
        shared_ptr<TorUtil::BufSock> _s;
    };

    namespace EVENT_STATE {
        enum state_t {
            PRISTINE,
            PRELISTEN,
            HEARTBEAT,
            HANDLING,
            POSTLISTEN,
            DONE,
        };
    };
    typedef enum EVENT_STATE::state_t event_state_t;

    class Event {
    public:
        Event(const string& event_name) : _event_name(event_name),
                                          _arrived_at(not_a_date_time),
                                          _state(EVENT_STATE::PRISTINE) {};

        const string _event_name;
        ptime _arrived_at;
        event_state_t _state;

        // need a virtual member function to use dynamic_cast
        virtual string toString() const { return "Event"; };
    };
    typedef shared_ptr<Event> EventPtr;

    class CircuitEvent : public Event {
        /* checked */
    public:
        CircuitEvent(const string& event_name, uint64_t circ_id, const string& status,
                     const vector<string>& path, const string& purpose, const string& reason,
                     const string& remote_reason) :
                     Event(event_name), _circ_id(circ_id), _status(status),
                     _path(path), _purpose(purpose), _reason(reason),
                     _remote_reason(remote_reason) {};
        string toString() const;

        const uint64_t _circ_id;
        string _status;
        vector<string> _path;
        string _purpose;
        string _reason;
        string _remote_reason;
    };
    class StreamEvent : public Event {
        /* checked */
    public:
        StreamEvent(const string& event_name, uint64_t strm_id, const string& status,
                    uint64_t circ_id, const string& target_host, uint16_t target_port,
                    const string& reason, const string& remote_reason, const string& source,
                    const string& source_addr, const string& purpose) :
                    Event(event_name),
                    _strm_id(strm_id), _status(status), _circ_id(circ_id),
                    _target_host(target_host), _target_port(target_port),
                    _reason(reason), _remote_reason(remote_reason),
                    _source(source), _source_addr(source_addr),
                    _purpose(purpose) {};
        string toString(const bool succinct=true) const;

        const uint64_t _strm_id; // "global_identifier" in Tor code.
        const string _status;
        const uint64_t _circ_id;
        string _target_host;
        uint16_t _target_port;
        string _reason;
        string _remote_reason;
        string _source;
        string _source_addr;
        string _purpose;
    };
    class ORConnEvent : public Event {
        /* checked */
    public:
        ORConnEvent(const string& event_name, const string& status, const string& endpoint,
                    int age, int read_bytes, int wrote_bytes,
                    const string& reason, int ncircs) :
                    Event(event_name), _status(status), _endpoint(endpoint),
                    _age(age), _read_bytes(read_bytes),
                    _wrote_bytes(wrote_bytes), _reason(reason), _ncircs(ncircs)
                    {};

        const string _status;
        const string _endpoint;
        const int _age;
        const int _read_bytes;
        const int _wrote_bytes;
        const string _reason;
        const int _ncircs;
    };
    class StreamBwEvent : public Event {
        /* checked */
    public:
        StreamBwEvent(const string& event_name, uint64_t strm_id,
                      unsigned long written, unsigned long read) :
                      Event(event_name), _strm_id(strm_id),
                      _bytes_written(written), _bytes_read(read)
                      {};
        
        const uint64_t _strm_id;
        const unsigned long _bytes_written;
        const unsigned long _bytes_read;
    };
    class NewDescEvent : public Event {
        /* checked */
    public:
        NewDescEvent(const string& event_name, const vector<string>& idlist) :
                     Event(event_name), _idlist(idlist)
                     {};

        vector<string> _idlist;
    };

    class NetworkStatus {
        /* checked */
    public:
        NetworkStatus(const string& nickname, const string& idhash, const string& orhash, const string& updated,
                      const string& ip, uint16_t orport, uint16_t dirport, const vector<string>& flags,
                      int32_t bandwidth=-1);
#if 0
        NetworkStatus(const NetworkStatus& other);
#endif
        string toString() const;

        string _nickname;
        string _idhash;
        string _orhash;
        string _ip;
        uint16_t _orport;
        uint16_t _dirport;
        vector<string> _flags;
        string _idhex;
        int32_t _bandwidth; // is -1 if not specified
        ptime _updated;
    };
    class NetworkStatusEvent : public Event {
        /* checked */
    public:
        NetworkStatusEvent(const string& event_name, const vector<NetworkStatusPtr > nslist) :
                            Event(event_name), _nslist(nslist)
                            {};
        
        vector<NetworkStatusPtr > _nslist;
    };
    class NewConsensusEvent : public NetworkStatusEvent {
    public:
        /* checked */
        NewConsensusEvent(const string& event_name, const vector<NetworkStatusPtr > nslist) :
                          NetworkStatusEvent(event_name, nslist) {};
    };

    class EventSink {
    public:
        virtual void heartbeat_event(Event* event) {};
        virtual void unknown_event(Event* event) {};
        virtual void circ_status_event(Event* event) {};
        virtual void stream_status_event(Event* event) {};
        virtual void stream_bw_event(Event* event) {};
        virtual void or_conn_status_event(Event* event) {};
        virtual void bandwidth_event(Event* event) {};
        virtual bool new_desc_event(Event* event) { return false; };
        virtual void msg_event(Event* event) {};
        virtual void ns_event(Event* event) {};
        virtual void new_consensus_event(Event* event) {};
        virtual void buildtimeout_set_event(Event* event) {};
        virtual void guard_event(Event* event) {};
        virtual void address_mapped_event(Event* event) {};
        virtual void timer_event(Event* event) {};
    };

    class EventHandler : public EventSink {
    public:
        void _handle1(ptime timestamp, const Connection::reply_t& lines);
        Connection* _c;

    private:
        EventPtr _decode1(const string& body, const string& data);
    };

    class ExitPolicyLine {
        /* Class to represent a line in a Router's exit policy in a
           way that can be easily checked.
        */
    public:
        ExitPolicyLine(bool match, string ip_mask, string port_low, string port_high);
        
        /* return true if the ip and port match this line, in which
         * case "accept" will be set/clear appropriately.  return
         * false if don't match this line, in which case "accept" is
         * not touched.
         */
        bool check(const string& ip, const uint16_t port, bool& accept) const;
        string toString() const;

        uint32_t _ip;
        uint32_t _netmask;
        uint16_t _port_low;
        bool _match;
        uint16_t _port_high;
    };

    class RouterVersion {
        /*
          """ Represents a Router's version. Overloads all comparison
          operators to check for newer, older, or equivalent
          versions. """
         */
    public:
        RouterVersion() : _valid(false) {}
        RouterVersion(const string& version);

        bool operator < (const RouterVersion& other) const {
            assert (_valid);
            return _version < other._version;
        };
        bool operator > (const RouterVersion& other) const {
            assert (_valid);
            return _version > other._version;
        };
        bool operator >= (const RouterVersion& other) const {
            assert (_valid);
            return _version >= other._version;
        };
        bool operator <= (const RouterVersion& other) const {
            assert (_valid);
            return _version <= other._version;
        };
        bool operator == (const RouterVersion& other) const {
            assert (_valid);
            return _version == other._version;
        };
        bool operator != (const RouterVersion& other) const {
            assert (_valid);
            return _version != other._version;
        };

        bool valid() const {
            return _valid;
        }

        int _version;
        string _ver_string;
    private:
        bool _valid;
    };

    class Router {
    public:
        /* "ns_bandwidth" should be -1 if not available. */
        Router(const string& idhex, const string& name, int bw, bool down,
               const vector<ExitPolicyLine>& exitpolicy, const vector<string>& flags,
               const string& ip, const string& version, const string& os, seconds uptime,
               ptime published, const string& contact, bool rate_limited,
               const string& orhash, int ns_bandwidth,
               const string& extra_info_digest);

        static RouterPtr build_from_desc(const vector<string>& desc, 
            const NetworkStatus& ns);
        // Somewhat hackish method to update this router to be a copy of "r"
        void update_to(const Router& r);
        // Check the entire exitpolicy to see if the router will allow
        // connections to 'ip':'port'
        bool will_exit_to(const string& ip, uint16_t port) const;

        bool operator==(const Router& other) { return _idhex == other._idhex; };
        string toString() const;

        ////
        static log4cxx::LoggerPtr _logger;

        string _idhex;
        string _nickname;
        int _bw;
        int _desc_bw;
        vector<ExitPolicyLine> _exitpolicy;
        vector<string> _flags;
        bool _down;
        uint32_t _ip;
        RouterVersion _version;
        string _os;
        int _list_rank; // position in a sorted list of routers.
        seconds _uptime;
        ptime _published;
        int _refcount; // How many open circs are we currently in?
        bool _deleted; // Has Tor already deleted this descriptor?
        string _contact;
        bool _rate_limited;
        string _orhash;
        string _extra_info_digest;
        vector<int> _generated;
    };

    class Consensus {
    public:
        Consensus(const map<string, NetworkStatusPtr >& ns_map,
                  const RouterPtrVecPtr& sorted_r,
                  const map<string, RouterPtr >& router_map,
                  const map<string, string>& nick_map,
                  int consensus_count)
                  : _ns_map(ns_map), _sorted_r(sorted_r),
                    _routers(router_map), _name_to_key(nick_map),
                    _consensus_count(consensus_count) {};
        const map<string, NetworkStatusPtr > _ns_map;
        const RouterPtrVecPtr _sorted_r;
        const map<string, RouterPtr >& _routers;
        const map<string, string>& _name_to_key;
        int _consensus_count;
    };
    typedef shared_ptr<Consensus> ConsensusPtr;

    class ConsensusTracker : public EventHandler {
    public:
        ConsensusTracker(Connection* c, bool consensus_only=true);
        virtual void update_consensus();
        virtual void new_consensus_event(const Event* n);
        virtual bool new_desc_event(const Event* d);
        virtual bool ns_event(const Event* d);
        ConsensusPtr current_consensus(void);

        map<string, NetworkStatusPtr > _ns_map;
        map<string, RouterPtr > _routers;
        RouterPtrVecPtr _sorted_r;
        map<string, string> _name_to_key;
        int _consensus_count;
        bool _consensus_only;

    private:
        void _update_consensus(const vector<NetworkStatusPtr >& nslist);
        void __update_sorted_r();
        void _sanity_check(RouterPtrVecPtr list);
        void _read_routers(const vector<NetworkStatusPtr >& nslist);

        static log4cxx::LoggerPtr _logger;
    };
}

#endif // TORCTL_HPP
