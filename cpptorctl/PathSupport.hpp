
#ifndef PATHSUPPORT_HPP
#define PATHSUPPORT_HPP

/* $Id$ */

#include <vector>
#include <string>
#include <set>
#include <exception>
#include <boost/date_time/posix_time/posix_time.hpp>

#include "TorCtl.hpp"
#include "common.hpp"

using std::list;
using std::vector;
using std::string;
using std::set;
using std::exception;
using namespace boost::posix_time;
using boost::regex;
using boost::regex_match;
using boost::regex_search;

using TorCtl::Router;
using TorCtl::RouterPtr;
using TorCtl::RouterPtrVecPtr;
using TorCtl::RouterVersion;
using TorCtl::ConsensusPtr;

namespace PathSupport {
    class Circuit;
    typedef shared_ptr<Circuit> CircuitPtr;
    class NodeRestrictionList;
    typedef shared_ptr<NodeRestrictionList> NodeRestrictionListPtr;

    class PathRestriction {
    public:
//        virtual ~PathRestriction() {};
        virtual bool path_is_ok(const vector<RouterPtr >& path) const = 0;
    };
    typedef shared_ptr<PathRestriction> PathRestrictionPtr;

    class RestrictionError : public runtime_error {
    public:
        RestrictionError() : runtime_error("<none specified>") {};
        explicit RestrictionError(const string& s) : runtime_error(s) {};
    };
    class NoNodesRemain : public RestrictionError {
    public:
        explicit NoNodesRemain(const string& s) : RestrictionError(s) {};
    };

    class NodeGenerator {
        /*
          "Interface for node generation"
         */
    public:
        virtual ~NodeGenerator() {}
        /*
          """Constructor. Takes a bandwidth-sorted list of Routers
          'sorted_r' and a NodeRestrictionList 'rstr_list'"""
         */
        NodeGenerator(const RouterPtrVecPtr sorted_r,
                      NodeRestrictionListPtr rstr_list)
            : _sorted_r(sorted_r), _rstr_list(rstr_list),
              _generating(false), _exhausted(false)
        {
            /* we want the child's rebuild() to be called, but c++
             * doesnt work that way (see
             * www.artima.com/cppsource/nevercall.html), so we no
             * longer call it here. The child should take care of
             * calling rebuild().
             */
            //rebuild(sorted_r);
        }

        virtual void rebuild(
            const RouterPtrVecPtr& sorted_r=RouterPtrVecPtr());
        virtual void mark_chosen(const RouterPtr& r) {
            Common::removeFromVectorOfPtrs(_routers, r, true);
        }
        virtual bool all_chosen() const {
            return 0 == _routers.size();
        }
        void reset_restriction(NodeRestrictionListPtr rstr_list);
        virtual void rewind();
        virtual void generate() = 0;
        virtual RouterPtr next() throw (NoNodesRemain) = 0;

    protected:
        void _doExhausted() throw (NoNodesRemain);

        RouterPtrVecPtr _sorted_r;
        NodeRestrictionListPtr _rstr_list;
        vector<RouterPtr > _rstr_routers;
        // subset of _rstr_routers that satisfies restrictions.
        vector<RouterPtr > _routers;

        // c++ doesnt have generator like python's "yield", so we roll
        // it ourselves. these vars keep the current 'state' of the
        // iteration.

        // true if we are "generating". when out of elements, should
        // clear this and set _exhausted.
        bool _generating;
        bool _exhausted;

    private:
        static log4cxx::LoggerPtr _logger;
    };
    typedef shared_ptr<NodeGenerator> NodeGeneratorPtr;

    class ExactUniformGenerator : public NodeGenerator {
    public:
        ExactUniformGenerator(RouterPtrVecPtr sorted_r,
                              NodeRestrictionListPtr rstr_list,
                              int position=0)
            : NodeGenerator(sorted_r, rstr_list), _position(position),
              _min_gen(0)
        {
            rebuild(sorted_r);
        }

        void rebuild(const RouterPtrVecPtr& sorted_r=RouterPtrVecPtr());
        void mark_chosen(const RouterPtr& r);
        void generate();
        RouterPtr next() throw (NoNodesRemain);

    private:
        int _position;
        vector<RouterPtr > _choices;
        int _min_gen;
        static log4cxx::LoggerPtr _logger;
    };

    class OrderedExitGenerator : public NodeGenerator {
        /*
          """NodeGenerator that produces exits in an ordered fashion
          for a specific port"""
         */
    public:
        OrderedExitGenerator(int to_port,
                             RouterPtrVecPtr sorted_r,
                             NodeRestrictionListPtr rstr_list)
            : NodeGenerator(sorted_r, rstr_list), _to_port(to_port),
              _last_idx(0)
        {
            rebuild(sorted_r);
        }

        void mark_chosen(const RouterPtr& r) {
            _next_exit_by_port[_to_port] += 1;
        }
        bool all_chosen() const {
            return _last_idx == Common::getFromMap(_next_exit_by_port,
                                                   _to_port);
        }
        void generate();
        RouterPtr next() throw (NoNodesRemain);
        virtual void rewind();
        void set_port(uint16_t port) {
            _to_port = port;
            rewind();
        }

    private:
        static log4cxx::LoggerPtr _logger;

        uint16_t _to_port;
        map<uint16_t, uint32_t> _next_exit_by_port;
        uint32_t _last_idx;
    };

    class BwWeightedGenerator : public NodeGenerator {
    public:
        BwWeightedGenerator(RouterPtrVecPtr sorted_r,
                            NodeRestrictionListPtr rstr_list,
                            int pathlen, bool exit, bool guard)
            : NodeGenerator(sorted_r, rstr_list),
              // _max_bandwidth(10000000),
              _exit(exit), _guard(guard),
              _total_bw(0), _total_exit_bw(0), _total_guard_bw(0),
              _total_weighted_bw(0), _pathlen(pathlen),
              _exit_weight(0), _guard_weight(0), _i(0)
        {
            rebuild(sorted_r);
        }

        void rebuild(const RouterPtrVecPtr& sorted_r=RouterPtrVecPtr());
        void generate();
        RouterPtr next() throw (NoNodesRemain);

    private:
//        const double _max_bandwidth;
        const bool _exit;
        const bool _guard;
        long double _total_bw;
        long double _total_exit_bw;
        long double _total_guard_bw;
        unsigned long long int _total_weighted_bw;
        const int _pathlen;
        long double _exit_weight;
        long double _guard_weight;

        static log4cxx::LoggerPtr _logger;

        // used by ::next()
        vector<RouterPtr>::iterator _router_it;
        long long int _i;
    };

    class PathSelector {
    public:
        vector<RouterPtr > select_path(const int pathlen);
        PathSelector(NodeGeneratorPtr entry_gen, NodeGeneratorPtr mid_gen,
                     NodeGeneratorPtr exit_gen,
                     PathRestrictionPtr path_restrict)
            : _entry_gen(entry_gen), _mid_gen(mid_gen), _exit_gen(exit_gen),
              _path_restrict(path_restrict) {}

        void rebuild_gens(const RouterPtrVecPtr& sorted_r);
        const NodeGeneratorPtr& exit_gen() const { return _exit_gen; }

    private:
        static log4cxx::LoggerPtr _logger;

        NodeGeneratorPtr _entry_gen;
        NodeGeneratorPtr _mid_gen;
        NodeGeneratorPtr _exit_gen;
        PathRestrictionPtr _path_restrict;
    };

    class NodeRestriction {
    public:
        virtual ~NodeRestriction() {};
        virtual bool r_is_ok(const RouterPtr& r) const = 0;
    };
    typedef shared_ptr<NodeRestriction> NodeRestrictionPtr;

    class MetaNodeRestriction : public NodeRestriction {
    public:
        virtual ~MetaNodeRestriction() {};
        virtual void add_restriction(NodeRestrictionPtr rstr) = 0;
//        virtual void next_rstr() = 0;
        virtual void del_restriction(string restrictionClass) = 0;
    };

    class MetaPathRestriction : public PathRestriction {
    public:
        virtual ~MetaPathRestriction() {};
        virtual void add_restriction(PathRestrictionPtr rstr) = 0;
        virtual void del_restriction(string restrictionClass) = 0;
    };

    class PathRestrictionList : public MetaPathRestriction {
        /*
          """Class to manage a list of PathRestrictions"""
         */
    public:
        PathRestrictionList() {};
        PathRestrictionList(vector<PathRestrictionPtr > restrictions) :
            _restrictions(restrictions) {};

        bool path_is_ok(const vector<RouterPtr >& path) const;
        void add_restriction(PathRestrictionPtr rstr) {
            _restrictions.push_back(rstr);
        };
        /*
          "Remove all PathRestrictions of type RestrictionClass from
          the list."
         */
        void del_restriction(string restrictionClass);

    private:
        static log4cxx::LoggerPtr _logger;
        vector<PathRestrictionPtr > _restrictions;
    };

    /***********************************************************/
    // node restrictions

    class FlagsRestriction : public NodeRestriction {
    public:
        FlagsRestriction(const vector<string>& mandatory,
                         const vector<string>& forbidden) :
            _mandatory(mandatory), _forbidden(forbidden) {};

        bool r_is_ok(const RouterPtr& router) const;

    private:
        const vector<string> _mandatory;
        const vector<string> _forbidden;
    };


    class NickRestriction : public NodeRestriction {
    public:
        NickRestriction(const string& nickname)
            : _nickname(nickname) {}
        bool r_is_ok(const RouterPtr& router) const {
            return router->_nickname == _nickname;
        }
    private:
        const string _nickname;
    };

    class IdHexRestriction : public NodeRestriction {
        /*
          """Require that the node idhash is as specified"""
         */
    public:
        IdHexRestriction(string idhex);

        bool r_is_ok(const RouterPtr& router) const {
            return router->_idhex == _idhex;
        };

    private:
        string _idhex;
    };

    class MinBwRestriction : public NodeRestriction {
        /*
          """Require a minimum bandwidth"""
         */
    public:
        MinBwRestriction(int minbw)
            : _min_bw(minbw) {}

        bool r_is_ok(const RouterPtr& router) const {
            return router->_bw >= _min_bw;
        };

    private:
        const int _min_bw;
    };

    class RateLimitedRestriction : public NodeRestriction {
    public:
        RateLimitedRestriction(bool limited=true)
            : _limited(limited) {}

        bool r_is_ok(const RouterPtr& router) const {
            return router->_rate_limited == _limited;
        };

    private:
        const bool _limited;
    };

    class VersionIncludeRestriction : public NodeRestriction {
        /*
          """Require that the version match one in the list"""
        */
    public:
        VersionIncludeRestriction(const vector<string> eq);

        bool r_is_ok(const RouterPtr& router) const {
            // TODO: this needs testing
            return Common::inVector(_eq, router->_version);
        }

    private:
        vector<RouterVersion> _eq;
    };

    class VersionExcludeRestriction : public NodeRestriction {
        /*
          """Require that the version not match one in the list"""
        */
    public:
        /*
          "Constructor. 'exclude' is a list of versions as strings"
         */
        VersionExcludeRestriction(const vector<string> exclude);

        bool r_is_ok(const RouterPtr& router) const {
            // TODO: this needs testing
            return !Common::inVector(_exclude, router->_version);
        }

    private:
        vector<RouterVersion> _exclude;
    };

    class VersionRangeRestriction : public NodeRestriction {
        /*
          """Require that the versions be inside a specified range"""
        */
    public:
        VersionRangeRestriction(const string gr_eq,
                                const string less_eq="");

        bool r_is_ok(const RouterPtr& router) const;

    private:
        RouterVersion _gr_eq;
        RouterVersion _less_eq;
    };

    class PercentileRestriction : public NodeRestriction {
        /*
          """Restriction to cut out a percentile slice of the
          network."""
         */
    public:
        /*
          """Constructor. Sets up the restriction such that routers in
          the 'pct_skip' to 'pct_fast' percentile of bandwidth
          rankings are returned from the sorted list 'r_list'"""
         */
        PercentileRestriction(double pct_skip, double pct_fast,
                              const RouterPtrVecPtr& r_list)
            : _pct_skip(pct_skip), _pct_fast(pct_fast), _sorted_r(r_list) {}

        /*
          "Returns true if r is in the percentile boundaries (by
          rank)"
         */
        bool r_is_ok(const RouterPtr& r) const;

    private:
        const double _pct_skip;
        const double _pct_fast;
        RouterPtrVecPtr _sorted_r;
    };

    class UptimeRestriction : public NodeRestriction {
    public:
        UptimeRestriction(seconds min_uptime=seconds(not_a_date_time),
                          seconds max_uptime=seconds(not_a_date_time))
            : _min_uptime(min_uptime), _max_uptime(max_uptime) {};

        bool r_is_ok(const RouterPtr& r) const;

    private:
        const seconds _min_uptime;
        const seconds _max_uptime;
    };

    class ConserveExitsRestriction : public NodeRestriction {
    public:
        ConserveExitsRestriction(const vector<uint16_t>& exit_ports=vector<uint16_t>())
            : _exit_ports(exit_ports) {};

        bool r_is_ok(const RouterPtr& r) const;

    private:
        const vector<uint16_t> _exit_ports;
    };

    class RankRestriction : public NodeRestriction {
        /*
          """Restriction to cut out a list-rank slice of the
          network."""
         */
    public:
        RankRestriction(int rank_skip, int rank_stop)
            : _rank_skip(rank_skip), _rank_stop(rank_stop) {};
        bool r_is_ok(const RouterPtr& r) const;

    private:
        const int _rank_skip;
        const int _rank_stop;
    };

    class OSRestriction : public NodeRestriction {
        /*
          "Restriction based on operating system"
         */
    public:
        /*
          """Constructor. Accept router OSes that match regexes in
          'ok', rejects those that match regexes in 'bad'."""
         */
        OSRestriction(const vector<regex>& ok,
                      const vector<regex>& bad=vector<regex>())
            : _ok(ok), _bad(bad) {};
        /*
          "Returns true if r is in 'ok', false if 'r' is in 'bad'. If
          'ok'"
         */
        bool r_is_ok(const RouterPtr& r) const;

    private:
        const vector<regex> _ok;
        const vector<regex> _bad;
    };

    class ExitPolicyRestriction : public NodeRestriction {
        /*
          """Require that a router exit to an ip+port"""
         */
    public:
        ExitPolicyRestriction(const string& to_ip,
                              const uint16_t& to_port)
            : _to_ip(to_ip), _to_port(to_port) {}
        bool r_is_ok(const RouterPtr& r) const {
            return r->will_exit_to(_to_ip, _to_port);
        }

    private:
        const string _to_ip;
        const uint16_t _to_port;
    };

    class OrNodeRestriction : public MetaNodeRestriction {
        /*
          MetaNodeRestriction that is the boolean or of two or more
          NodeRestrictions
        */
    public:
        /*
          "Constructor. 'rs' is a list of NodeRestrictions"          
        */
        OrNodeRestriction(const vector<NodeRestrictionPtr >& rs)
            : _rstrs(rs) {}
        /*
          "Returns true if one of 'rs' is true for this router"
         */
        bool r_is_ok(const RouterPtr& r) const;
        void add_restriction(NodeRestrictionPtr restr) {}
        void del_restriction(string restrictionClass) {}

    private:
        const vector<NodeRestrictionPtr > _rstrs;
    };

    class NodeRestrictionList : public MetaNodeRestriction {
    public:
        NodeRestrictionList() {};
        NodeRestrictionList(const vector<NodeRestrictionPtr >& restrictions)
            : _restrictions(restrictions) {}

        bool r_is_ok(const RouterPtr& r) const;
        void add_restriction(NodeRestrictionPtr restr) {
            _restrictions.push_back(restr);
        };
        void del_restriction(string restrictionClass);
        void clear() {
            _restrictions.clear();
        };
        size_t num_restrictions() const { return _restrictions.size(); }

    private:
        static log4cxx::LoggerPtr _logger;
        vector<NodeRestrictionPtr > _restrictions;
    };

    /***********************************************************/
    //  path restrictions

    class UniqueRestriction : public PathRestriction {
    public:
        bool path_is_ok(const vector<RouterPtr >& path) const;
    };

    class Subnet16Restriction : public PathRestriction {
    public:
        bool path_is_ok(const vector<RouterPtr >& path) const;
    };

    /***********************************************************/
    class BaseSelectionManager {
    public:
        BaseSelectionManager() : _bad_restrictions(false) {}

        bool _bad_restrictions;
        ConsensusPtr _consensus;
    };

    /***********************************************************/
    class SelectionManager : public BaseSelectionManager {
    public:
        SelectionManager(int pathlen, bool order_exits,
                         double percent_fast, double percent_skip,
                         double min_bw,
                         bool use_all_exits, bool uniform,
                         string use_exit, bool use_guards,
                         /* geoip_config=None, */
                         bool restrict_guards=false,
                         /* NodeRestriction* extra_node_rstr=NULL, */
                         vector<uint16_t> exit_ports=vector<uint16_t>())
            : _pathlen(pathlen), _order_exits(order_exits),
              _percent_fast(percent_fast), _percent_skip(percent_skip),
              _min_bw(min_bw), _use_all_exits(use_all_exits), _uniform(uniform),
              _exit_id(use_exit), _use_guards(use_guards),
              _restrict_guards_only(restrict_guards),
              /*_extra_node_rstr(extra_node_rstr),*/ _exit_ports(exit_ports)
        {}

        vector<RouterPtr > select_path();
        void new_consensus(ConsensusPtr consensus);
        void set_target(const string& ip, const uint16_t& port);
        bool reconfigure(ConsensusPtr consensus=ConsensusPtr());
        bool set_exit(const string& exit_name);

    private:
        static log4cxx::LoggerPtr _logger;

        int _pathlen;
        bool _order_exits;
        double _percent_fast;
        double _percent_skip;
        double _min_bw;
        bool _use_all_exits;
        bool _uniform;
        string _exit_id;
        bool _use_guards;
        bool _restrict_guards_only;
        shared_ptr<PathSelector> _path_selector;
        /*NodeRestrictionPtr _extra_node_rstr;*/
        vector<uint16_t> _exit_ports;
        NodeRestrictionListPtr _exit_rstr;
        shared_ptr<PathRestrictionList> _path_rstr;

        void _reconfigure(ConsensusPtr consensus);
        void _set_exit(string exit_name);
    };

    /***********************************************************/
    class Stream {
    public:
        Stream(const uint64_t& sid, const string& host,
               const uint16_t& port, const string& kind)
            : _strm_id(sid), _host(host), _port(port), _kind(kind),
              _attached_at(not_a_date_time), _bytes_read(0), _bytes_written(0),
              _failed(false), _ignored(false) {}

        bool operator==(const Stream& other) const { return _strm_id == other._strm_id; }
        // hack to ensure always using pointers of Stream. UPDATE:
        // 01/17/12: allow copy constructor for now because
        // isValueInVectorOfPtrs() comparision will require it, and at
        // time of writing, should be ok to copy a stream object
        // Stream(const Stream& other) : _strm_id(other._strm_id)
        //     { THROW_USE_POINTERS("Stream"); }
        Stream& operator=(const Stream& other) { THROW_USE_POINTERS("Stream"); }

        string toString(const bool succinct=true) const;
        time_duration lifespan(ptime now) const {
            return now - _attached_at;
        }

        const uint64_t _strm_id;
        vector<uint64_t> _detached_from;
        CircuitPtr _pending_circ;
        CircuitPtr _circ;
        string _host;
        uint16_t _port;
        string _kind;
        ptime _attached_at;
        uint64_t _bytes_read;
        uint64_t _bytes_written;
        bool _failed;
        bool _ignored;
    };
    typedef shared_ptr<Stream> StreamPtr;

    class Circuit {
    public:
        Circuit();
        // hack to ensure always using pointers of Circuit
        Circuit(const Circuit& other) { THROW_USE_POINTERS("Circuit"); }
        Circuit& operator=(const Circuit& other) { THROW_USE_POINTERS("Circuit"); }

        vector<string> id_path() const;

        uint64_t _circ_id;
        vector<RouterPtr > _path;
        RouterPtr _exit;
        bool _built;
        bool _failed;
        bool _dirty;
        bool _requested_closed;
        bool _detached_cnt;
        ptime _last_extended_at;
        vector<time_duration> _extend_times;
        time_duration _setup_duration;
        vector<StreamPtr > _pending_streams;
        // _carried_streams
    };

    class Connection : public TorCtl::Connection {
    public:
        Connection(tcp::socket& sock) : TorCtl::Connection(sock) {};

        CircuitPtr build_circuit(const vector<RouterPtr > path);
    };

    class PathBuilder : public TorCtl::ConsensusTracker {
    public:
        PathBuilder(PathSupport::Connection* c, SelectionManager& selmgr);
        vector<CircuitPtr > circuit_list();
        void circ_status_event(TorCtl::Event* c_arg);
        void stream_status_event(TorCtl::Event* s_arg);
        void stream_bw_event(TorCtl::Event* s_arg);
        void new_consensus_event(TorCtl::Event* n_arg);
        bool new_desc_event(TorCtl::Event* d_arg);
        virtual void attach_stream_any(StreamPtr& stream,
                                       const vector<uint64_t>& badcircs);

        /* schedule_low_prio(), schedule_selmgr() not
         * used. schedule_immediate() only used by schedule_selmgr(),
         * so not used either
         *
         * heartbeat_event() not used. is_urgent_event() only used by
         * heartbeat_event(), so not used either
         */

        RouterPtr _last_exit;
        // new_nym. not necessary
        static const int _resolve_port = 0; // looks like this is always 0
        uint16_t _num_circuits;
        map<uint64_t, CircuitPtr > _circuits;
        map<uint64_t, StreamPtr > _streams;
        SelectionManager& _selmgr;
//         ThreadSafeQueue imm_jobs
//         ThreadSafeQueue low_prio_jobs
        bool _run_all_jobs;
        bool _do_reconfigure;
//         strm_selector

    private:
        static log4cxx::LoggerPtr _logger;
    };

    class CircuitHandler : public PathBuilder {
    public:
        CircuitHandler(PathSupport::Connection* c, SelectionManager& selmgr,
                       const int num_circuits);
        void circ_status_event(TorCtl::Event* c_arg);

    private:
        static log4cxx::LoggerPtr _logger;

        void check_circuit_pool();
        CircuitPtr build_circuit(const string& host, const uint16_t& port);
    };

    /* StreamHandler that extends from the CircuitHandler to handle
     * attaching streams to an appropriate circuit in the pool.
     */
    class StreamHandler : public CircuitHandler {
    public:
        StreamHandler(PathSupport::Connection* c, SelectionManager& selmgr,
                      const int num_circs)
            : CircuitHandler(c, selmgr, num_circs) {}

        void stream_status_event(TorCtl::Event* s_arg);

        void close_stream(const uint64_t& id, const uint8_t& reason);
    };
}

#endif // PATHSUPPORT_HPP
