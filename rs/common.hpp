
#ifndef COMMON_HPP
#define COMMON_HPP

/* $Id$ */

#include <vector>
#include <map>
#include <string>

using std::string;

namespace Common {

    class NotYet : public std::runtime_error {
    public:
        NotYet() : std::runtime_error("not yet ... error") {}
        explicit NotYet(const string& s) :
            std::runtime_error("not yet " + s) {}
    };

#if 0
    template<typename T>
    bool
    inVectorOfPtrs(const std::vector<shared_ptr<T> >& v, const shared_ptr<T>& e)
    {
        BOOST_FOREACH(shared_ptr<T> ie, v) {
            if (*ie == *e) {
                return true;
            }
        }
        return false;
    }
#endif

    // BE CAREFUL when comparing pointers. two objects might have
    // identical values (they are copies), but their address pointers
    // are different and will be considered different.
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
        throw Common::NotYet(string() + "handled at " + __FILE__ + ":" + \
                             boost::lexical_cast<string>(__LINE__));    \
    }                                                                   \
    while (false)

#define THROW_NYT()                                                     \
    do {                                                                \
        throw Common::NotYet(string() + "tested at " + __FILE__ + ":" + \
                             boost::lexical_cast<string>(__LINE__));    \
    }                                                                   \
    while (false)

#define THROW_USE_POINTERS(cls)                                         \
    do {                                                                \
        throw runtime_error("Fatal Error! Should use only "             \
                            "pointers of class " cls);                  \
    }                                                                   \
    while (false)

#endif // COMMON_HPP
