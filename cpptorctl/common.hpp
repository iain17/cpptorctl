
#ifndef COMMON_HPP
#define COMMON_HPP

/* $Id$ */

#include <vector>
#include <map>
#include <boost/lambda/lambda.hpp>

#define ARRAY_LEN(arr) (sizeof (arr) / sizeof ((arr)[0]))

#define QUOTE(str) #str
#define EXPAND_AND_QUOTE(str) QUOTE(str)

namespace Common {

    class NotYet : public std::runtime_error {
    public:
        NotYet() : std::runtime_error("not yet ... error") {}
        explicit NotYet(const std::string& s) :
            std::runtime_error("not yet " + s) {}
    };

    /*
     * this assumes the vector contains pointers (specifically those
     * that can clean up themselves automatically --- e.g. boost
     * shared_ptr --- otherwise memory leak occurs), and will compare
     * the pointers' dereferenced values to look for the element e to
     * remove. first=true means only remove the first found occurence;
     * otherwise remove all.
     *
     * return number of removed elements.
     */
    template<typename T>
    int
    removeFromVectorOfPtrs(std::vector<T>& v, const T& e,
                           const bool first=true)
    {
        int num_removed = 0;
        typename std::vector<T>::iterator it = v.begin();
        while (it != v.end()) {
            if ((*(*it)) == (*e)) {
                it = v.erase(it);
                ++num_removed;
                if (first) {
                    break;
                }
            }
            else {
                ++it;
            }
        }
        return num_removed;
    }
    
    /*
     * this assumes the vector contains pointers, and will compare the
     * pointers' dereferenced values
     */
    template<typename T>
    inline bool
    isValueInVectorOfPtrs(const std::vector<T>& v, const T& e)
    {
        return v.end() != std::find_if(v.begin(), v.end(),
                                       *(boost::lambda::_1) == *e);
    }

    // BE CAREFUL when comparing pointers. two objects might have
    // identical values (they are copies), but their address pointers
    // are different and will be considered different. and vice versa.
    //
    // also see isValueInVectorOfPtrs().
    template<typename T>
    inline bool
    inVector(const std::vector<T>& v, const T& e)
    {
        return v.end() != std::find(v.begin(), v.end(), e);
    }

    /* std::remove() is funky: after a successful remove, the vector
     * size remains the same, and so if you loop based on the size or
     * even iterator end(), it will still show the removed element.
     */
    template<typename T>
    static void
    removeFromVector(std::vector<T>& v, const T& e)
    {
        size_t i = 0;
        for (; i < v.size(); i++) {
            if (e == v[i]) {
                break;
            }
        }
        if (i < v.size()) {
            v.erase(v.begin() + i);
        }
    };

    template<typename T1, typename T2>
    inline bool
    inMap(const std::map<T1, T2>& m, const T1& k)
    {
        return m.end() != m.find(k);
    }

    // assumes the k exists in the map.
    //
    // the main purpose of this is to make use of const maps
    // easier. because a "value = map[key];" with a const map doesn't
    // compile (because the operator [] is implicitly
    // "(*((this->insert(make_pair(x,T()))).first)).second", which
    // modifies the map if the key doesnt exist).
    template<typename T1, typename T2>
    inline const T2&
    getFromMap(const std::map<T1, T2>& m, const T1& k)
    {
        return m.find(k)->second;
    }
}

#define THROW_NYH()                                                     \
    do {                                                                \
        throw Common::NotYet(std::string() + "handled at " + __FILE__ + ":" + \
                             boost::lexical_cast<std::string>(__LINE__));    \
    }                                                                   \
    while (false)

#define THROW_NYT()                                                     \
    do {                                                                \
        throw Common::NotYet(std::string() + "tested at " + __FILE__ + ":" + \
                             boost::lexical_cast<std::string>(__LINE__));    \
    }                                                                   \
    while (false)

#define THROW_USE_POINTERS(cls)                                         \
    do {                                                                \
        throw runtime_error("Fatal Error! Should use only "             \
                            "pointers of class " cls);                  \
    }                                                                   \
    while (false)

#endif // COMMON_HPP
