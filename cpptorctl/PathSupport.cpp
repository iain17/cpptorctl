
#include <boost/foreach.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/algorithm/string/regex.hpp>
#include <boost/make_shared.hpp>
#include <boost/lexical_cast.hpp>
#include <stdio.h>
#include <sstream>
#include <boost/algorithm/string/join.hpp>
#include <cxxabi.h>

#include "PathSupport.hpp"
#include "common.hpp"
#include "Log.hpp"

using boost::regex;
using boost::regex_match;
using boost::regex_search;
using boost::make_shared;
using std::endl;
using boost::lexical_cast;
using std::stringstream;

using namespace PathSupport;
using TorCtl::ConsensusPtr;

static const char rcsid[] =
    "$Id$";

#define INIT_CLASS_LOGGER(clsname)                                      \
    log4cxx::LoggerPtr clsname::_logger(                                \
        log4cxx::Logger::getLogger("PathSupport." EXPAND_AND_QUOTE(clsname)))


INIT_CLASS_LOGGER(NodeGenerator);
INIT_CLASS_LOGGER(ExactUniformGenerator);
INIT_CLASS_LOGGER(OrderedExitGenerator);
INIT_CLASS_LOGGER(BwWeightedGenerator);
INIT_CLASS_LOGGER(PathSelector);
INIT_CLASS_LOGGER(SelectionManager);
INIT_CLASS_LOGGER(PathBuilder);
INIT_CLASS_LOGGER(CircuitHandler);
INIT_CLASS_LOGGER(NodeRestrictionList);
INIT_CLASS_LOGGER(PathRestrictionList);

/***********************************************************/

bool
PathRestrictionList::path_is_ok(const vector<RouterPtr >& path) const
{
    BOOST_FOREACH(const PathRestrictionPtr& rs, _restrictions) {
        // it's ok to look for pointers since we're looking for
        // elements within this list itself.
        if (!(*rs).path_is_ok(path)) {
            return false;
        }
    }
    return true;
}

/******************/
void
PathRestrictionList::del_restriction(string restrictionClass)
{
    vector<PathRestrictionPtr > newlist;
    BOOST_FOREACH(const PathRestrictionPtr& rstr, _restrictions) {
        int status;
        shared_ptr<char> elemfullname(
            abi::__cxa_demangle(typeid(*rstr).name(), 0, 0, &status),
            std::ptr_fun(free));
        LOGDEBUG("real elem type name: " << elemfullname);
        if (restrictionClass != elemfullname.get()) {
            newlist.push_back(rstr);
        }
    }
    _restrictions = newlist;
    return;
}

/***********************************************************/

void
NodeGenerator::reset_restriction(NodeRestrictionListPtr rstr_list)
{
    _rstr_list = rstr_list;
    rebuild();
}

/******************/

void
NodeGenerator::rewind()
{
    LOGDEBUG("begin");
    _generating = false;
    _routers = _rstr_routers; // shallow copy
    if (0 == _routers.size()) {
        LOGNOTICE("No routers left after restrictions applied");
        throw NoNodesRemain("No routers left after restrictions applied");
    }
    LOGDEBUG("_routers.size() " << _rstr_routers.size());
    LOGDEBUG("done");
}

/******************/

void
NodeGenerator::rebuild(const RouterPtrVecPtr& sorted_r)
{
    LOGDEBUG("begin");
    if (sorted_r) {
        LOGDEBUG("using input sorted_r. size " << sorted_r->size());
        _sorted_r = sorted_r;
    }
    _rstr_routers.clear();
    BOOST_FOREACH(const RouterPtr& r, (*_sorted_r)) {
        if ((*_rstr_list).r_is_ok(r)) {
            _rstr_routers.push_back(r);
        }
    }
    if (_rstr_routers.size() == 0) {
        LOGNOTICE("No routers left after restrictions applied");
        throw NoNodesRemain("No routers left after restrictions applied");
    }
    LOGDEBUG("_rstr_routers.size() " << _rstr_routers.size());
    LOGDEBUG("done");
    return;
}

/******************/

void
NodeGenerator::_doExhausted() throw (NoNodesRemain)
{
    _generating = false;
    _exhausted = true;
    throw NoNodesRemain("exhausted generator");
}

/***********************************************************/

CircuitPtr
Connection::build_circuit(const vector<RouterPtr > path)
{
    CircuitPtr circ = make_shared<Circuit>();
    circ->_path = path;
    circ->_exit = circ->_path.back();
    circ->_circ_id = extend_circuit(0, circ->id_path());
    return circ;
}

/***********************************************************/

/* Node restrictions */

bool
PercentileRestriction::r_is_ok(const RouterPtr& r) const
{
    if (r->_list_rank < (((double)(*_sorted_r).size()) * _pct_skip / 100)) {
        return false;
    }
    else if (r->_list_rank > (((double)(*_sorted_r).size()) * _pct_fast / 100)) {
        return false;
    }
    return true;
}

bool
UptimeRestriction::r_is_ok(const RouterPtr& r) const
{
    if (!_min_uptime.is_special() && r->_uptime < _min_uptime) {
        return false;
    }
    if (!_max_uptime.is_special() && r->_uptime > _max_uptime) {
        return false;
    }
    return true;
}

bool
RankRestriction::r_is_ok(const RouterPtr& r) const
{
    if (!r->_list_rank < _rank_skip) {
        return false;
    }
    else if (!r->_list_rank > _rank_stop) {
        return false;
    }
    return true;
}

bool
OSRestriction::r_is_ok(const RouterPtr& r) const
{
    BOOST_FOREACH(const regex& y, _ok) {
        if (regex_search(r->_os, y)) {
            return true;
        }
    }
    BOOST_FOREACH(const regex& b, _bad) {
        if (regex_search(r->_os, b)) {
            return false;
        }
    }
    if (_ok.size()) {
        return false;
    }
    if (_bad.size()) {
        return true;
    }
    return false;
}

bool
ConserveExitsRestriction::r_is_ok(const RouterPtr& r) const
{
    if (_exit_ports.size()) {
        BOOST_FOREACH(const uint16_t& port, _exit_ports) {
            if (r->will_exit_to("255.255.255.255", port)) {
                return false;
            }
        }
        return true;
    }
    return !Common::inVector(r->_flags, string("Exit"));
}

bool
FlagsRestriction::r_is_ok(const RouterPtr& router) const
{
    BOOST_FOREACH(const string& m, _mandatory) {
        if (!Common::inVector(router->_flags, m)) {
            return false;
        }
    }
    BOOST_FOREACH(const string& f, _forbidden) {
        if (Common::inVector(router->_flags, f)) {
            return false;
        }
    }
    return true;
}

IdHexRestriction::IdHexRestriction(string idhex)
{
    if (idhex[0] == '$') {
        _idhex = idhex.substr(1);
    }
    else {
        _idhex = idhex;
    }
    boost::algorithm::to_upper(_idhex);
}

VersionIncludeRestriction::VersionIncludeRestriction(const vector<string> eq)
{
    BOOST_FOREACH(const string& rv, eq) {
        _eq.push_back(RouterVersion(rv));
    }
}

VersionExcludeRestriction::VersionExcludeRestriction(const vector<string> exclude)
{
    BOOST_FOREACH(const string& rv, exclude) {
        _exclude.push_back(RouterVersion(rv));
    }
}

VersionRangeRestriction::VersionRangeRestriction(const string gr_eq,
                                                 const string less_eq)
    : _gr_eq(gr_eq)
{
    if (less_eq.length()) {
        assert (!_less_eq.valid());
        _less_eq = less_eq;
    }
}

bool
VersionRangeRestriction::r_is_ok(const RouterPtr& router) const
{
    return ((router->_version >= _gr_eq)
            && (!_less_eq.valid() || router->_version <= _less_eq));
}

bool
OrNodeRestriction::r_is_ok(const RouterPtr& r) const
{
    BOOST_FOREACH(const NodeRestrictionPtr& rs, _rstrs) {
        if ((*rs).r_is_ok(r)) {
            return true;
        }
    }
    return false;
}

void
NodeRestrictionList::del_restriction(string restrictionClass)
{
    LOGDEBUG("deleting clsname: " << restrictionClass);
    vector<NodeRestrictionPtr > newlist;
    BOOST_FOREACH(const NodeRestrictionPtr& rstr, _restrictions) {
        int status;
        shared_ptr<char> elemfullname(
            abi::__cxa_demangle(typeid(*rstr).name(), 0, 0, &status),
            std::ptr_fun(free));
        LOGDEBUG("real elem type name: " << elemfullname);
        if (restrictionClass != elemfullname.get()) {
            newlist.push_back(rstr);
        }
    }
    _restrictions = newlist;
    return;
}

bool
NodeRestrictionList::r_is_ok(const RouterPtr& r) const
{
    BOOST_FOREACH(const NodeRestrictionPtr& rs, _restrictions) {
        if (!(*rs).r_is_ok(r)) {
            return false;
        }
    }
    return true;
}

/***********************************************************/

/* path restrictions */

bool
Subnet16Restriction::path_is_ok(const vector<RouterPtr >& path) const
{
    uint32_t mask16;
    assert (1 == inet_pton(AF_INET, "255.255.0.0", &mask16));

    uint32_t ip16 = path[0]->_ip & mask16;
    BOOST_FOREACH(const RouterPtr& r, path) {
        if (ip16 == (r->_ip & mask16)) {
            return false;
        }
    }
    return true;
}

bool
UniqueRestriction::path_is_ok(const vector<RouterPtr >& path) const
{
    for (size_t i = 0; i < path.size(); ++i) {
        if ((path.begin()+i) != std::find_if(path.begin(), path.begin()+i,
                                             *(boost::lambda::_1)==*(path[i])))
        {
            return false;
        }
    }
    return true;
}

/***********************************************************/

void
ExactUniformGenerator::generate()
{
    LOGDEBUG("begin");
    _generating = true;
    _choices.clear();

    // get all the routers that have been generated/used the fewest
    // times.

    LOGDEBUG("_routers.size() " << _routers.size());
    assert (_routers.size() > 0);

    int min_gen = _routers[0]->_generated[_position];
    BOOST_FOREACH(const RouterPtr& r, _routers) {
        min_gen = std::min((r->_generated[_position]), min_gen);
    }

    BOOST_FOREACH(const RouterPtr& r, _routers) {
        if ((r->_generated[_position]) == min_gen) {
            _choices.push_back(r);
        }
    }
    _min_gen = min_gen;
    LOGDEBUG("_min_gen " << _min_gen);
    LOGDEBUG("_choices.size() " << _choices.size());
    LOGDEBUG("done");
}

/******************/

void
ExactUniformGenerator::mark_chosen(const RouterPtr& r)
{
    r->_generated[_position] += 1;
    NodeGenerator::mark_chosen(r);
}

/******************/

void
ExactUniformGenerator::rebuild(const RouterPtrVecPtr& sorted_r)
{
    LOGDEBUG("begin");
    NodeGenerator::rebuild(sorted_r);
    BOOST_FOREACH(const RouterPtr& r, _rstr_routers) {
        int lgen = r->_generated.size();
        if (lgen < (_position+1)) {
            for (int i = lgen; i < (_position+1); ++i) {
                r->_generated.push_back(0);
            }
        }
    }
    LOGDEBUG("done");
}

/******************/

RouterPtr
ExactUniformGenerator::next() throw (NoNodesRemain)
{
    LOGDEBUG("begin");
    assert (_generating);
    if (_choices.size() == 0) {
        _generating = false;
        LOGNOTICE("Ran out of choices in ExactUniformGenerator. Incrementing nodes");
        assert (_routers.size() > 0);
        BOOST_FOREACH(const RouterPtr& r, _routers) {
            if ((r->_generated[_position]) == _min_gen) {
                r->_generated[_position] += 1;
            }
        }
        _doExhausted();
    }
    int random = rand() % (_choices.size());
    RouterPtr retval = _choices[random];

    _choices.erase(_choices.begin() + random);
    LOGDEBUG("_choices.size() " <<_choices.size());
    LOGDEBUG("done");
    return retval;
}

/***********************************************************/

void
OrderedExitGenerator::rewind()
{
    LOGDEBUG("begin");
    NodeGenerator::rewind();
    if (!Common::inMap(_next_exit_by_port, _to_port) || !_next_exit_by_port[_to_port])
    {
        _next_exit_by_port[_to_port] = 0;
        _last_idx = _routers.size();
    }
    else {
        _last_idx = _next_exit_by_port[_to_port];
    }
    LOGDEBUG("done");
}

/******************/

void
OrderedExitGenerator::generate()
{
    _generating = true;
}

/******************/

RouterPtr
OrderedExitGenerator::next() throw (NoNodesRemain)
{
    // TODO: not tested
    assert(_generating);
    RouterPtr r;
    if (_last_idx == _next_exit_by_port[_to_port]) {
        _doExhausted();
    }
    if (_next_exit_by_port[_to_port] >= _routers.size()) {
        _next_exit_by_port[_to_port] = 0;
    }
    _next_exit_by_port[_to_port] += 1;
    return _routers[_next_exit_by_port[_to_port]];
}

/***********************************************************/

void
BwWeightedGenerator::rebuild(const RouterPtrVecPtr& sorted_r)
{
    // TODO not tested
    LOGDEBUG("begin");
    NodeGenerator::rebuild(sorted_r);
    NodeGenerator::rewind();
    _total_exit_bw = _total_guard_bw = _total_bw = 0;
    BOOST_FOREACH(const RouterPtr& r, _routers) {
        _total_bw += r->_bw;
        if (Common::inVector(r->_flags, string("Exit"))) {
            _total_exit_bw += r->_bw;
        }
        if (Common::inVector(r->_flags, string("Guard"))) {
            _total_guard_bw += r->_bw;
        }
    }

    long double bw_per_hop = ((long double)_total_bw) / _pathlen;

    long double e_ratio = 0;
    long double g_ratio = 0;
    if (_total_bw > 0) {
        e_ratio = (_total_exit_bw) / _total_bw;
        g_ratio = (_total_guard_bw) / _total_bw;
    }
    LOGDEBUG(
        "E = " << (_total_exit_bw) <<
        ", G = " <<(_total_guard_bw) <<
        ", T = " <<(_total_bw) <<
        ", g_ratio = " <<(g_ratio) << ", e_ratio = " <<(e_ratio) <<
        ", bw_per_hop = " <<(bw_per_hop));

    if (_exit) {
        _exit_weight = 1;
    }
    else {
        if (_total_exit_bw < bw_per_hop) {
            // Don't use exit nodes at all
            _exit_weight = 0;
        }
        else {
            if (_total_exit_bw > 0) {
                _exit_weight = (_total_exit_bw - bw_per_hop) / _total_exit_bw;
            }
            else {
                _exit_weight = 0;
            }
        }
    }

    if (_guard) {
        _guard_weight = 1;
    }
    else {
        if (_total_guard_bw < bw_per_hop) {
            _guard_weight = 0;
        }
        else {
            if (_total_guard_bw > 0) {
                _guard_weight = (_total_guard_bw - bw_per_hop) / _total_guard_bw;
            }
            else {
                _guard_weight = 0;
            }
        }
    }

    long double tmp_total_weighted_bw = 0;
    BOOST_FOREACH(const RouterPtr& r, _routers) {
        long double bw = r->_bw;
        if (Common::inVector(r->_flags, string("Exit"))) {
            bw *= _exit_weight;
        }
        if (Common::inVector(r->_flags, string("Guard"))) {
            bw *= _guard_weight;
        }
        tmp_total_weighted_bw += bw;
    }

    _total_weighted_bw = (unsigned long long int)tmp_total_weighted_bw;
    LOGDEBUG("Bw: "<<(_total_weighted_bw)<<"/"<<(_total_bw)
             <<". The exit-weight is: "<<(_exit_weight)
             << ", guard weight is: "<<(_guard_weight));
    LOGDEBUG("done");
}

/******************/

void
BwWeightedGenerator::generate()
{
    _generating = true;
    _router_it = _routers.begin();
}

/******************/

RouterPtr
BwWeightedGenerator::next() throw (NoNodesRemain)
{
    // TODO not tested
    // this one doesnt exhaust
    LOGDEBUG("begin");
    assert(_generating);
    while (true) {
        if (_router_it == _routers.begin()) {
            if (_total_weighted_bw) {
                _i = rand() % _total_weighted_bw;
            }
            else {
                _i = 0;
            }
        }

        while (_router_it != _routers.end()) {
            if (_i < 0) {
                _router_it = _routers.begin();
                break;
            }

            RouterPtr r = *_router_it;
            int bw = r->_bw;
            if (Common::inVector(r->_flags, string("Exit"))) {
                bw *= _exit_weight;
            }
            if (Common::inVector(r->_flags, string("Guard"))) {
                bw *= _guard_weight;
            }
            _i -= bw;
            ++_router_it;
            if (_i < 0) {
                LOGDEBUG("Chosen router with nick " << r->_nickname
                         << " with a bandwidth of: " <<r->_bw);
                return r;
            }
        }
    }
}

/***********************************************************/

void
PathSelector::rebuild_gens(const RouterPtrVecPtr& sorted_r)
{
    (*_entry_gen).rebuild(sorted_r);
    (*_mid_gen).rebuild(sorted_r);
    (*_exit_gen).rebuild(sorted_r);
}

/******************/

vector<RouterPtr >
PathSelector::select_path(int pathlen)
{
    // 2011-12-20 21:24:00 -0600 (Tue, 20 Dec 2011):
    // (eyeballed) matches python. but not tested
    vector<RouterPtr > path;

    LOGDEBUG("begin");

    (*_entry_gen).rewind();
    (*_mid_gen).rewind();
    (*_exit_gen).rewind();

    NodeGenerator& entry = *_entry_gen;
    NodeGenerator& mid = *_mid_gen;
    NodeGenerator& ext = *_exit_gen;

    entry.generate();
    mid.generate();
    ext.generate();

    LOGDEBUG("Selecting path..");

    while (true) {
        path.clear();
        LOGDEBUG("Building path..");
        try {
            if (pathlen == 1) {
                path.push_back(ext.next());
            }
            else {
                path.push_back(entry.next());
                for (int i = 1; i < (pathlen-1); ++i) {
                    path.push_back(mid.next());
                }
                path.push_back(ext.next());
            }
            LOGDEBUG("check path validity");
            if ((*_path_restrict).path_is_ok(path)) {
                (*_entry_gen).mark_chosen(path[0]);
                for (int i = 1; i < (pathlen-1); ++i) {
                    (*_mid_gen).mark_chosen(path[i]);
                }
                (*_exit_gen).mark_chosen(path[pathlen-1]);
                LOGDEBUG("Marked path.");
                break;
            }
            else {
                LOGDEBUG("Path rejected by path restrictions.");
            }
        }
        catch (NoNodesRemain& e) {
            LOGNOTICE("Ran out of routers during buildpath..");
            (*_entry_gen).rewind();
            (*_mid_gen).rewind();
            (*_exit_gen).rewind();

            entry.generate();
            mid.generate();
            ext.generate();
        }
    }
    BOOST_FOREACH(const RouterPtr& r, path) {
        r->_refcount += 1;
        LOGDEBUG("Circ refcount "<<(r->_refcount)<<" for "<<r->_idhex);
    }
    LOGDEBUG("done");
    return path;
}

/******************/

bool
SelectionManager::reconfigure(ConsensusPtr consensus)
{
    try {
        _reconfigure(consensus);
        _bad_restrictions = false;
    }
    catch (NoNodesRemain) {
        LOGWARN("No nodes remain in selection manager");
        _bad_restrictions = true;
    }
    return _bad_restrictions;
}

/******************/

void
SelectionManager::_reconfigure(ConsensusPtr consensus)
{
    /* 2011-12-20 21:24:00 -0600 (Tue, 20 Dec 2011)
       (eyeballed) matches python, but not tested
     */
    LOGDEBUG("begin");

    static const vector<string> flags_running_fast =
        boost::assign::list_of("Running")("Fast");
    static const vector<string> flags_badexit(1, "BadExit");

    if (consensus) {
        LOGDEBUG("Reconfigure with consensus");
        _consensus = consensus;
    }
    else {
        LOGDEBUG("Reconfigure without consensus");
    }

    RouterPtrVecPtr sorted_r = _consensus->_sorted_r;

    _path_rstr = make_shared<PathRestrictionList>();
    LOGDEBUG("_use_all_exits " << _use_all_exits);
    if (_use_all_exits) {
        (*_path_rstr).add_restriction(make_shared<UniqueRestriction>());
    }
    else {
        (*_path_rstr).add_restriction(make_shared<Subnet16Restriction>());
        (*_path_rstr).add_restriction(make_shared<UniqueRestriction>());
    }

    vector<string> entry_flags;
    LOGDEBUG("_use_guards " << _use_guards);
    if (_use_guards) {
        entry_flags = boost::assign::list_of("Guard")("Running")("Fast");
        assert (3 == entry_flags.size());
        assert (entry_flags[0] == string("Guard"));
        assert (entry_flags[1] == string("Running"));
        assert (entry_flags[2] == string("Fast"));
    }
    else {
        entry_flags = flags_running_fast;
    }

    double nonentry_skip, nonentry_fast;
    if (_restrict_guards_only) {
        nonentry_skip = 0;
        nonentry_fast = 100;
    }
    else {
        nonentry_skip = _percent_skip;
        nonentry_fast = _percent_fast;
    }

    ///
    LOGDEBUG("prepare entry restrictions");
    NodeRestrictionListPtr entry_rstr = make_shared<NodeRestrictionList>();
    {
        vector<NodeRestrictionPtr > ornoderestrictionArgs;
        ornoderestrictionArgs.push_back(
            make_shared<FlagsRestriction>(flags_badexit, vector<string>()));
        ornoderestrictionArgs.push_back(
            make_shared<ConserveExitsRestriction>(_exit_ports));

        entry_rstr->add_restriction(
            make_shared<PercentileRestriction>(
                _percent_skip, _percent_fast, sorted_r));
        entry_rstr->add_restriction(
            make_shared<OrNodeRestriction>(ornoderestrictionArgs));
        entry_rstr->add_restriction(
            make_shared<FlagsRestriction>(entry_flags, vector<string>()));
    }

    ///
    LOGDEBUG("prepare middle restrictions");
    NodeRestrictionListPtr mid_rstr = make_shared<NodeRestrictionList>();
    {
        vector<NodeRestrictionPtr > ornoderestrictionArgs;
        ornoderestrictionArgs.push_back(
            make_shared<FlagsRestriction>(flags_badexit, vector<string>()));
        ornoderestrictionArgs.push_back(
            make_shared<ConserveExitsRestriction>(_exit_ports));
        assert(2 == ornoderestrictionArgs.size());

        mid_rstr->add_restriction(
            make_shared<PercentileRestriction>(
                nonentry_skip, nonentry_fast, sorted_r));
        mid_rstr->add_restriction(
            make_shared<OrNodeRestriction>(ornoderestrictionArgs));
        mid_rstr->add_restriction(
            make_shared<FlagsRestriction>(flags_running_fast, vector<string>()));
    }

    ///
    
    LOGDEBUG("prepare exit restrictions");
    _exit_rstr = make_shared<NodeRestrictionList>();
    if (_exit_id.length()) {
        _set_exit(_exit_id);
        LOGDEBUG("Applying Setexit: "<<_exit_id);
        _exit_rstr->add_restriction(make_shared<IdHexRestriction>(_exit_id));
    }
    else if (_use_all_exits) {
        _exit_rstr->add_restriction(
            make_shared<FlagsRestriction>(flags_running_fast, flags_badexit));
    }
    else {
        _exit_rstr->add_restriction(
            make_shared<PercentileRestriction>(
                nonentry_skip, nonentry_fast, sorted_r));
        _exit_rstr->add_restriction(
            make_shared<FlagsRestriction>(flags_running_fast, flags_badexit));
    }

    /*
    if self.extra_node_rstr:
      entry_rstr.add_restriction(self.extra_node_rstr)
      mid_rstr.add_restriction(self.extra_node_rstr)
      self.exit_rstr.add_restriction(self.extra_node_rstr)
    */

    LOGDEBUG("create exit node generator");
    NodeGeneratorPtr exitgen;
    if (_order_exits) {
        THROW_NYH();
    }
    else if (_uniform) {
        THROW_NYT();
        exitgen = make_shared<ExactUniformGenerator>(sorted_r, _exit_rstr);
    }
    else {
        exitgen = make_shared<BwWeightedGenerator>(sorted_r, _exit_rstr,
                                                   _pathlen, true, false);
    }

    LOGDEBUG("create path selector");
    if (_uniform) {
        THROW_NYT();
        _path_selector = make_shared<PathSelector>(
            make_shared<ExactUniformGenerator>(sorted_r, entry_rstr),
            make_shared<ExactUniformGenerator>(sorted_r, mid_rstr),
            exitgen, _path_rstr);
    }
    else {
        size_t oldnum = entry_rstr->num_restrictions();
        entry_rstr->del_restriction("PathSupport::OrNodeRestriction");
        assert ((oldnum - 1) == entry_rstr->num_restrictions());

        oldnum = mid_rstr->num_restrictions();
        mid_rstr->del_restriction("PathSupport::OrNodeRestriction");
        assert ((oldnum - 1) == mid_rstr->num_restrictions());

        _path_selector = make_shared<PathSelector>(
            make_shared<BwWeightedGenerator>(sorted_r, entry_rstr, _pathlen,
                                             false, _use_guards),
            make_shared<BwWeightedGenerator>(sorted_r, mid_rstr, _pathlen,
                                             false, false),
            exitgen, _path_rstr);
    }

    LOGDEBUG("done");
    return;
}

/******************/

void
SelectionManager::_set_exit(string exit_name)
{
    /* 2011-12-20 21:24:00 -0600 (Tue, 20 Dec 2011)
     * (eyeballed) matched python
     */
    string exit_id;
    if (exit_name.length()) {
        if (exit_name[0] == '$') {
            exit_id = exit_name;
        }
        else if (Common::inMap(_consensus->_name_to_key, exit_name)) {
            exit_id = Common::getFromMap(_consensus->_name_to_key, exit_name);
        }
    }
    _exit_id = exit_id;
}

/******************/

bool
SelectionManager::set_exit(const string& exit_name)
{
    /* 2011-12-20 21:24:00 -0600 (Tue, 20 Dec 2011)
     * (eyeballed) matched python
     */
    THROW_NYT();
    _set_exit(exit_name);
    _exit_rstr->clear();
    if (!_exit_id.length()) {
        LOGNOTICE("Requested null exit "<<_exit_id);
        _bad_restrictions = true;
    }
    else if (!Common::inMap(_consensus->_routers, _exit_id.substr(1))) {
        LOGNOTICE("Requested absent exit "<<(_exit_id));
        _bad_restrictions = true;
    }
    else if (Common::getFromMap(_consensus->_routers,
                                _exit_id.substr(1))->_down)
    {
        const Router& e = *(Common::getFromMap(_consensus->_routers,
                                               _exit_id.substr(1)));
        LOGNOTICE("Requested downed exit "<<(_exit_id)
                  <<" (bw: "<<(e._bw)<<", flags: "
                  <<boost::join((e._flags), ",") << ")");
        _bad_restrictions = true;
    }
    else if (Common::getFromMap(_consensus->_routers,
                                _exit_id.substr(1))->_deleted)
    {
        const Router& e = *(Common::getFromMap(_consensus->_routers,
                                               _exit_id.substr(1)));
        LOGNOTICE("Requested deleted exit "<<_exit_id<<" (bw: "<<e._bw
                  <<", flags: "<<boost::join(e._flags, ",")<<", Down: "<<e._down
                  <<", ref: "<<e._refcount<<")");
        _bad_restrictions = true;
    }
    else {
        _exit_rstr->add_restriction(make_shared<IdHexRestriction>(_exit_id));
        LOGDEBUG("Added exit restriction for "<<_exit_id);
        try {
            _path_selector->exit_gen()->rebuild();
            _bad_restrictions = false;
        }
        catch (const RestrictionError& e) {
            LOGWARN("Restriction error "<<e.what()<<" after set_exit");
            _bad_restrictions = true;
        }
    }
    return _bad_restrictions;
}

/***********************************************************/

void
SelectionManager::new_consensus(ConsensusPtr consensus)
{
    _consensus = consensus;
    try {
        _path_selector->rebuild_gens(_consensus->_sorted_r);
        if (_exit_id.length()) {
            set_exit(_exit_id);
        }
    }
    catch (NoNodesRemain& e) {
        LOGNOTICE("No viable nodes in consensus for restrictions.");
    }
    return;
}

/******************/

void
SelectionManager::set_target(const string& ip, const uint16_t& port)
{
    if (_bad_restrictions) {
        LOGWARN("Requested target with bad restrictions");
        throw RestrictionError();
    }
    _exit_rstr->del_restriction("PathSupport::ExitPolicyRestriction");
    _exit_rstr->add_restriction(make_shared<ExitPolicyRestriction>(ip, port));
    // if self.__ordered_exit_gen: self.__ordered_exit_gen.set_port(port)

    // Need to rebuild exit generator
    _path_selector->exit_gen()->rebuild();
    
    return;
}

/******************/

vector<RouterPtr >
SelectionManager::select_path()
{
    if (_bad_restrictions) {
        LOGWARN("Requested target with bad restrictions");
        throw RestrictionError();
    }
    return _path_selector->select_path(_pathlen);
}

/***********************************************************/

Circuit::Circuit()
{
    /* 2011-12-20 21:24:00 -0600 (Tue, 20 Dec 2011) */
    _circ_id = 0;
    _built = _failed = _dirty = _requested_closed = false;
    _detached_cnt = 0;
    _last_extended_at = microsec_clock::local_time();
    _setup_duration = not_a_date_time;
}

/******************/

vector<string>
Circuit::id_path() const
{
    /* 2011-12-20 21:24:00 -0600 (Tue, 20 Dec 2011) */
    vector<string> retval;
    BOOST_FOREACH(const RouterPtr& r, _path) {
        retval.push_back(r->_idhex);
    }
    return retval;
}

/*******************************************************/
string
Stream::toString(const bool succinct) const
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
        s << "strm: ";
        ADD_TO_S_SUCCINCT("id", strm_id);
        if (_circ.get()) {
            s << "cid=" << (_circ->_circ_id) << " ";
        }
        if (_pending_circ.get()) {
            s << "pcid=" << (_pending_circ->_circ_id) << " ";
        }
        ADD_TO_S_SUCCINCT("h", host);
        ADD_TO_S_SUCCINCT("p", port);
        ADD_TO_S_SUCCINCT("k", kind);
        ADD_TO_S_SUCCINCT("f", failed);
        ADD_TO_S_SUCCINCT("i", ignored);
    }
    else {
        ADD_TO_S(strm_id);

        s << ("pending circ: ")
          << (_pending_circ.get() ?
              lexical_cast<string>(_pending_circ->_circ_id) : "<none>")
          << "\n";
        s << ("circ: ")
          << (_circ.get() ? lexical_cast<string>(_circ->_circ_id) : "<none>")
          << "\n";

        ADD_TO_S(host);
        ADD_TO_S(port);
        ADD_TO_S(kind);

        s << "attached_at: " << (_attached_at) << "\n";

        ADD_TO_S(bytes_read);
        ADD_TO_S(bytes_written);
        ADD_TO_S(failed);
        ADD_TO_S(ignored);
    }

#undef ADD_TO_S

    return s.str();
}

/*******************************************************/
PathBuilder::PathBuilder(PathSupport::Connection* c, SelectionManager& selmgr)
    : TorCtl::ConsensusTracker(c), _selmgr(selmgr)
{
    /* 2011-12-20 21:24:00 -0600 (Tue, 20 Dec 2011) */
    _num_circuits = 1;
    _run_all_jobs = _do_reconfigure = false;
    _selmgr.reconfigure(current_consensus());
    LOGINFO("Read "<<_sorted_r->size()<<"/"<<_ns_map.size()<<" routers");
}

vector<CircuitPtr >
PathBuilder::circuit_list()
{
    /* 2011-12-20 21:24:00 -0600 (Tue, 20 Dec 2011) */
    vector<CircuitPtr > retval;
    for (map<uint64_t, CircuitPtr >::iterator it = _circuits.begin();
         it != _circuits.end(); ++it)
    {
        retval.push_back(it->second);
    }
    return retval;
}

void
PathBuilder::attach_stream_any(StreamPtr& stream,
                               const vector<uint64_t>& badcircs)
{
    LOGDEBUG("begin");
    /* 2011-12-20 21:24:00 -0600 (Tue, 20 Dec 2011) */
    vector<StreamPtr > unattached_streams =
        boost::assign::list_of(stream);
    // new_nym is only true when ScanHandler sets it, which we dont
    bool found_usable_circ = false;
    CircuitPtr circ;
    BOOST_FOREACH(circ, circuit_list()) {
        if (circ->_built && !circ->_requested_closed && !circ->_dirty &&
            !Common::inVector(badcircs, circ->_circ_id))
        {
            if (circ->_exit->will_exit_to(stream->_host, stream->_port)) {
                try {
                    _c->attach_stream(stream->_strm_id, circ->_circ_id);
                    stream->_pending_circ = circ;
                    circ->_pending_streams.push_back(stream);
                }
                catch (const TorCtl::ErrorReply& e) {
                    LOGWARN("Error attaching new stream: "
                            << e.what());
                    return;
                }
                found_usable_circ = true;
                break;
            }
        }
    }
    if (!found_usable_circ) {
        LOGINFO("could not find any usable circ -> need to build a new circ");
        circ.reset();
        try {
            _selmgr.set_target(stream->_host, stream->_port);
            circ = dynamic_cast<PathSupport::Connection*>(_c)->build_circuit(
                _selmgr.select_path());
        }
        catch (RestrictionError& e) {
            _last_exit.reset();
            LOGWARN("Closing impossible stream "<<stream->_strm_id<<" ("
                    <<e.what()<<")");
            try {
                //END_STREAM_REASON_EXITPOLICY
                _c->close_stream(stream->_strm_id, 4);
            }
            catch (TorCtl::ErrorReply& e) {
                LOGWARN("Error closing stream: "<<e.what());
            }
            return;
        }
        catch (TorCtl::ErrorReply& e) {
            LOGWARN("Error building circ: "<<e.what());
            _last_exit.reset();
            LOGNOTICE("Closing stream "<<stream->_strm_id);
            try {
                // END_STREAM_REASON_DESTROY
                _c->close_stream(stream->_strm_id, 5);
            }
            catch (TorCtl::ErrorReply& e) {
                LOGWARN("Error closing stream: "<<e.what());
            }
            return;
        }
#if 0
        BOOST_FOREACH(const StreamPtr& u, unattached_streams) {
            LOGDEBUG(
                "Attaching "<<u->_strm_id<<" pending build of "<<circ._circ_id);
            u->_pending_circ = circ;
            circ->_pending_streams.push_back(u);
        }
#else
        // only the "new_nym == true" block adds more elements to
        // unattached_streams
        assert(unattached_streams.size() == 1);
#endif
        _circuits[circ->_circ_id] = circ;
    }
    _last_exit = circ->_exit;
    LOGDEBUG("Set last exit to "<<_last_exit->_idhex);
    LOGDEBUG("done");
    return;
}

void
PathBuilder::circ_status_event(TorCtl::Event* c_arg)
{
    /* 2011-12-20 21:24:00 -0600 (Tue, 20 Dec 2011) */
    const TorCtl::CircuitEvent& c =
        *(dynamic_cast<TorCtl::CircuitEvent*>(c_arg));
    // just for debuggin
    vector<string> output =
        boost::assign::list_of
        (lexical_cast<string>(microsec_clock::local_time() - c._arrived_at))
        (c._event_name)
        (lexical_cast<string>(c._circ_id));
    if (c._path.size()) { output.push_back(boost::join(c._path, ",")); }
    if (c._reason.length()) { output.push_back("REASON=" + c._reason); }
    if (c._remote_reason.length()) { output.push_back("REMOTE_REASON=" +
                                                      c._remote_reason); }
    LOGDEBUG(boost::join(output, " "));

    if (!Common::inMap(_circuits, c._circ_id)) {
        LOGDEBUG("Ignoring circ " <<c._circ_id);
        return;
    }
    if (c._status == "EXTENDED") {
        _circuits[c._circ_id]->_last_extended_at = c._arrived_at;
    }
    else if (c._status == "FAILED" || c._status == "CLOSED") {
        const CircuitPtr& circ = _circuits[c._circ_id];
        BOOST_FOREACH(const RouterPtr& r, circ->_path) {
            r->_refcount -= 1;
            LOGDEBUG("Close refcount "<<r->_refcount<<" for "<<r->_idhex);
            if (r->_deleted && r->_refcount == 0) {
                LOGINFO("Purging expired router "<<r->_idhex);
                _routers.erase(r->_idhex);
            }
            _selmgr.new_consensus(current_consensus());
        }
        _circuits.erase(c._circ_id);
        BOOST_FOREACH(StreamPtr& stream, circ->_pending_streams) {
            if (!circ->_built) {
                LOGDEBUG("Finding new circ for "<<stream->_strm_id);
                attach_stream_any(stream, stream->_detached_from);
            }
            else {
                LOGNOTICE("Waiting on Tor to hint about stream "
                          <<stream->_strm_id<<" on closed circ "
                          <<circ->_circ_id);
            }
        }
    }
    else if (c._status == "BUILT") {
        _circuits[c._circ_id]->_built = true;
        try {
            BOOST_FOREACH(const StreamPtr& stream,
                          _circuits[c._circ_id]->_pending_streams)
            {
                _c->attach_stream(stream->_strm_id, c._circ_id);
            }
        }
        catch (const TorCtl::ErrorReply& e) {
            LOGNOTICE("Error attaching pending stream: "<<e.what());
            return;
        }
    }
}

/*******************/
void
PathBuilder::stream_status_event(TorCtl::Event* s_arg)
{
    /* 2011-12-20 21:24:00 -0600 (Tue, 20 Dec 2011) */
    TorCtl::StreamEvent& s = *(dynamic_cast<TorCtl::StreamEvent*>(s_arg));

    // only for debug
    vector<string> output =
        boost::assign::list_of
        (lexical_cast<string>(microsec_clock::local_time() - s._arrived_at))
        (s._event_name)
        (lexical_cast<string>(s._strm_id))
        (s._status)
        (lexical_cast<string>(s._circ_id))
        (s._target_host)
        (lexical_cast<string>(s._target_port))
        ;
    if (s._reason.length()) { output.push_back("REASON=" + s._reason); }
    if (s._remote_reason.length()) { output.push_back("REMOTE_REASON=" +
                                                      s._remote_reason); }
    if (s._purpose.length()) { output.push_back("PURPOSE=" + s._purpose); }
    if (s._source_addr.length()) { output.push_back("SOURCE_ADDR=" +
                                                    s._source_addr); }
    LOGDEBUG(boost::join(output, " "));

    if (!regex_match(s._target_host, regex("\\d+.\\d+.\\d+.\\d+"))) {
        s._target_host = "255.255.255.255";
    }

    // Hack to ignore Tor-handled streams
    if (Common::inMap(_streams, s._strm_id) && _streams[s._strm_id]->_ignored) {
        if (s._status == "CLOSED") {
            LOGDEBUG("Deleting ignored stream: " <<s._strm_id);
            _streams.erase(s._strm_id);
        }
        else {
            LOGDEBUG("Ignoring stream: " << s._strm_id);
        }
        return;
    }

    if (s._status == "NEW" || s._status == "NEWRESOLVE") {
        if (s._status == "NEWRESOLVE" && s._target_port == 0) {
            s._target_port = _resolve_port;
        }
        if (s._circ_id == 0) {
            _streams[s._strm_id] = make_shared<Stream>(
                s._strm_id, s._target_host, s._target_port, s._status);
        }
        else if (!Common::inMap(_streams, s._strm_id)) {
            LOGNOTICE("Got new stream " << s._strm_id << " with circuit "
                      << s._circ_id << " already attached.");
            _streams[s._strm_id] = make_shared<Stream>(
                s._strm_id, s._target_host, s._target_port, s._status);
            // XXX/TODO: stream objects don't have _circ_id members.
            // _streams[s._strm_id]->_circ_id = s._circ_id;
        }

        // Remember Tor-handled streams (Currently only directory
        // streams)

        if (s._purpose.length() && s._purpose.find("DIR_") == 0) {
            _streams[s._strm_id]->_ignored = true;
            LOGDEBUG("Ignoring stream: " << s._strm_id);
            return;
        }
        else if (s._source_addr.length()) {
            LOGWARN("assuming all detected streams are for us to handle");
//            THROW_NYH();
            // TODO: check with strm_selector
        }

        if (s._circ_id == 0) {
            LOGDEBUG("we need to attach stream " << s._strm_id);
            attach_stream_any(_streams[s._strm_id],
                              _streams[s._strm_id]->_detached_from);
        }
    }
    else if (s._status == "DETACHED") {
        if (!Common::inMap(_streams, s._strm_id)) {
            LOGWARN("Detached stream " << s._strm_id << " not found");
            _streams[s._strm_id] = make_shared<Stream>(
                s._strm_id, s._target_host, s._target_port, "NEW");
        }
        if (!s._circ_id) {
            if (s._reason == "TIMEOUT" || s._reason == "EXITPOLICY") {
                LOGNOTICE("Stream " << s._strm_id << " detached with "
                          << s._reason);
            }
            else {
                LOGWARN("Stream " << (s._strm_id)
                        << " detached from no circuit with reason: "
                        << (s._reason));
            }
        }
        else {
            LOGDEBUG("adding circ " << s._circ_id << " to stream "
                     << s._strm_id << " detached_from list");
            _streams[s._strm_id]->_detached_from.push_back(s._circ_id);
        }

        if (_streams[s._strm_id]->_pending_circ
            && Common::isValueInVectorOfPtrs(
                _streams[s._strm_id]->_pending_circ->_pending_streams,
                _streams[s._strm_id]))
        {
            LOGDEBUG("remove stream " << s._strm_id << " from circ " <<
                     _streams[s._strm_id]->_pending_circ->_circ_id <<
                     "'s pendings streams");
            const int num_removed = Common::removeFromVectorOfPtrs(
                _streams[s._strm_id]->_pending_circ->_pending_streams,
                _streams[s._strm_id],
                false);
            assert (1 == num_removed);
        }

        _streams[s._strm_id]->_pending_circ.reset();
        assert (!_streams[s._strm_id]->_pending_circ);
        LOGDEBUG("try to attach stream " << s._strm_id << " to another circ");
        attach_stream_any(_streams[s._strm_id],
            _streams[s._strm_id]->_detached_from);
    }
    else if (s._status == "SUCCEEDED") {
        if (!Common::inMap(_streams, s._strm_id)) {
            LOGNOTICE("Succeeded stream " << s._strm_id << " not found");
            return;
        }
        if (s._circ_id &&
            _streams[s._strm_id]->_pending_circ->_circ_id != s._circ_id)
        {
            LOGWARN("Mismatch of pending: "
                    <<_streams[s._strm_id]->_pending_circ->_circ_id<<" vs "
                    <<(s._circ_id));
            if (Common::inMap(_circuits, s._circ_id)) {
                _streams[s._strm_id]->_circ = _circuits[s._circ_id];
            }
            else {
                LOGNOTICE("Stream " << s._strm_id << " has unknown circuit: "
                          << s._circ_id);
            }
        }
        else {
            _streams[s._strm_id]->_circ = _streams[s._strm_id]->_pending_circ;
        }
        uint32_t oldsize = _streams[s._strm_id]->_pending_circ->_pending_streams.size();

        assert (1 == Common::removeFromVectorOfPtrs(
                    _streams[s._strm_id]->_pending_circ->_pending_streams,
                    _streams[s._strm_id],
                    false));

        assert ((oldsize - 1) ==
                _streams[s._strm_id]->_pending_circ->_pending_streams.size());
        _streams[s._strm_id]->_pending_circ.reset();
        _streams[s._strm_id]->_attached_at = s._arrived_at;
    }
    else if (s._status == "FAILED" || s._status == "CLOSED") {
        if (!Common::inMap(_streams, s._strm_id)) {
            LOGNOTICE("Failed stream " << s._strm_id << " not found");
            return;
        }
        
        if (!s._circ_id) {
            if (s._reason == "TIMEOUT" || s._reason == "EXITPOLICY") {
                LOGNOTICE("Stream " <<s._strm_id << " " << s._status << " with "
                          << s._reason);
            }
            else {
                LOGWARN("Stream " << s._strm_id << " " << s._status
                        << " from no circuit with reason: " << s._reason);
            }
        }
        // We get failed and closed for each stream. OK to return and
        // let the closed do the cleanup
        if (s._status == "FAILED") {
            // Avoid busted circuits that will not resolve or carry
            // traffic.
            _streams[s._strm_id]->_failed = true;
            if (Common::inMap(_circuits, s._circ_id)) {
                _circuits[s._circ_id]->_dirty = true;
            }
            else if (s._circ_id != 0) {
                LOGWARN("Failed stream " << s._strm_id << " on unknown circ "
                        << s._circ_id);
            }
            return;
        }
        
        if (_streams[s._strm_id]->_pending_circ) {
            uint32_t oldsize = _streams[s._strm_id]->_pending_circ->_pending_streams.size();

            assert (1 == Common::removeFromVectorOfPtrs(
                        _streams[s._strm_id]->_pending_circ->_pending_streams,
                        _streams[s._strm_id],
                        false));

            assert ((oldsize - 1) ==
                    _streams[s._strm_id]->_pending_circ->_pending_streams.size());
        }
        _streams.erase(s._strm_id);
    }
    else if (s._status == "REMAP") {
        if (!Common::inMap(_streams, s._strm_id)) {
            LOGWARN("Remap id " << (s._strm_id) << " not found");
        }
        else {
            if (!regex_match(s._target_host, regex("\\d+.\\d+.\\d+.\\d+"))) {
                s._target_host = "255.255.255.255";
                LOGNOTICE("Non-IP remap for " << (s._strm_id) << " to "
                          << s._target_host);
            }
            _streams[s._strm_id]->_host = s._target_host;
            _streams[s._strm_id]->_port = s._target_port;
        }
    }
}

/*******************/
void
PathBuilder::stream_bw_event(TorCtl::Event* s_arg)
{
    /* 2011-12-20 21:24:00 -0600 (Tue, 20 Dec 2011) */
    TorCtl::StreamBwEvent& s = *(dynamic_cast<TorCtl::StreamBwEvent*>(s_arg));

    // only for debug
    vector<string> output =
        boost::assign::list_of
        (lexical_cast<string>(microsec_clock::local_time() - s._arrived_at))
        (s._event_name)
        (lexical_cast<string>(s._strm_id))
        (lexical_cast<string>(s._bytes_written))
        (lexical_cast<string>(s._bytes_read))
        ;

    if (!Common::inMap(_streams, s._strm_id)) {
        LOGDEBUG(boost::join(output, " "));
        LOGWARN("BW event for unknown stream id: "<<s._strm_id);
    }
    else {
        if (!_streams[s._strm_id]->_ignored) {
            LOGDEBUG(boost::join(output, " "));
        }
        _streams[s._strm_id]->_bytes_read += s._bytes_read;
        _streams[s._strm_id]->_bytes_written += s._bytes_written;
    }
}

/*******************/
void
PathBuilder::new_consensus_event(TorCtl::Event* n_arg)
{
    TorCtl::ConsensusTracker::new_consensus_event(n_arg);
    _selmgr.new_consensus(current_consensus());
}

/*******************/
bool
PathBuilder::new_desc_event(TorCtl::Event* d_arg)
{
    if (TorCtl::ConsensusTracker::new_desc_event(d_arg)) {
        _selmgr.new_consensus(current_consensus());
    }
    return false;
}

/**********************************************************************/
CircuitHandler::CircuitHandler(
    PathSupport::Connection* c, SelectionManager& selmgr,
    const int num_circuits)
    : PathBuilder(c, selmgr)
{
    c->set_event_handler(this);
    this->_num_circuits = num_circuits;
    this->check_circuit_pool();
}

/*******************/
void
CircuitHandler::check_circuit_pool()
{
    /* 2011-12-20 21:24:00 -0600 (Tue, 20 Dec 2011) */
    int n = _circuits.size();
    int i = _num_circuits - n;
    if (i > 0) {
        LOGINFO("Checked pool of circuits: we need to build "
                <<i<<" circuits");
    }
    // Schedule (num_circs-n) circuit-buildups
    while (n < _num_circuits) {
        // TODO: Should mimic Tor's learning here
        build_circuit("255.255.255.255", 80);
        LOGDEBUG("Scheduled circuit No. " <<(n+1));
        n += 1;
    }
    return;
}

/*******************/
CircuitPtr
CircuitHandler::build_circuit(const string& host, const uint16_t& port)
{
    /* 2011-12-20 21:24:00 -0600 (Tue, 20 Dec 2011) */
    CircuitPtr circ;
    while (NULL == circ) {
        try {
            _selmgr.set_target(host, port);
            circ = dynamic_cast<PathSupport::Connection*>(_c)->build_circuit(
                _selmgr.select_path());
            assert (circ != NULL);
            _circuits[circ->_circ_id] = circ;
            return circ;
        }
        catch (RestrictionError& e) {
            LOGERROR("Impossible restrictions: "<<e.what());
        }
        catch (TorCtl::ErrorReply& e) {
            LOGWARN("Error building circuit: " <<e.what());
        }
    }
    return circ;
}

/*******************/
void
CircuitHandler::circ_status_event(TorCtl::Event* c_arg)
{
    /* 2011-12-20 21:24:00 -0600 (Tue, 20 Dec 2011) */
    TorCtl::CircuitEvent& c = *(dynamic_cast<TorCtl::CircuitEvent*>(c_arg));

    // only for debug
    vector<string> output = boost::assign::list_of
                            (c._event_name)
                            (lexical_cast<string>(c._circ_id))
                            (lexical_cast<string>(c._status))
                            ;

    if (c._path.size()) { output.push_back(boost::join(c._path, ",")); }
    if (c._reason.length()) { output.push_back("REASON=" + c._reason); }
    if (c._remote_reason.length()) { output.push_back("REMOTE_REASON=" +
                                                      c._remote_reason); }
    LOGDEBUG(boost::join(output, " "));

    // Circuits we don't control get built by Tor
    if (!Common::inMap(_circuits,c._circ_id)) {
        LOGDEBUG("Ignoring circuit " <<c._circ_id << " (controlled by Tor)");
        return;
    }

    if (c._status == "EXTENDED") {
        time_duration extend_time = c._arrived_at
                                    - _circuits[c._circ_id]->_last_extended_at;
        _circuits[c._circ_id]->_extend_times.push_back(extend_time);
        LOGINFO("Circuit " <<c._circ_id <<" extended in "<<
                extend_time<< " sec");
        _circuits[c._circ_id]->_last_extended_at = c._arrived_at;
    }
    else if (c._status == "FAILED" || c._status == "CLOSED") {
        PathBuilder::circ_status_event(c_arg);
        check_circuit_pool();
        return;
    }
    else if (c._status == "BUILT") {
        PathBuilder::circ_status_event(c_arg);
        CircuitPtr circ = _circuits[c._circ_id];
        circ->_setup_duration = time_duration::unit();
        BOOST_FOREACH(const time_duration& duration, circ->_extend_times) {
            circ->_setup_duration += duration;
        }
        LOGINFO("Circuit " <<c._circ_id<< " needed " <<
                circ->_setup_duration<< " seconds to be built");
    }
}

/**********************************************************************/
void
StreamHandler::stream_status_event(TorCtl::Event* s_arg)
{
    // we don't do anything, just call parent's.
    CircuitHandler::stream_status_event(s_arg);
}

void
StreamHandler::close_stream(const uint64_t& id, const uint8_t& reason)
{
    _c->close_stream(id, reason);
}

