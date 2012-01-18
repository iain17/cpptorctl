#include <stdio.h>
#include <iostream>
#include <vector>
#include <stdio.h>

#include <algorithm>
#include <boost/make_shared.hpp>
#include <assert.h>
#include <boost/make_shared.hpp>
#include <boost/ref.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/foreach.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/assign/list_of.hpp>

#include "../common.hpp"

static const char rcsid[] =
    "$Id$";

using std::exception;
using std::cout;
using std::endl;
using std::vector;
using std::string;
using boost::shared_ptr;
using boost::make_shared;

class obj {
public:
    obj() {}
    obj(int val) : _val(val) {}
    int getval() const {return _val;}
    bool operator == (const obj& other) const {
        cout << "operator == called with this and other val: " << _val << ", " << other._val << endl;
        return _val == other._val;
    }

private:
    int _val;
};

int testRemoveVectorOfPtrs()
{
    vector<shared_ptr<obj> > vec;

    shared_ptr<obj> a = make_shared<obj>(1);
    shared_ptr<obj> b = make_shared<obj>(2);
    shared_ptr<obj> c = make_shared<obj>(3);
    shared_ptr<obj> d = make_shared<obj>(4);
    shared_ptr<obj> e = make_shared<obj>(5);
    shared_ptr<obj> f = make_shared<obj>(2);

    vec.push_back(a);
    vec.push_back(b);
    vec.push_back(c);
    vec.push_back(d);
    vec.push_back(e);
    vec.push_back(f);

    {
        // test ARRAY_LEN
        static char a[0];
        assert (ARRAY_LEN(a) == 0);
        static char b[133];
        assert (ARRAY_LEN(b) == 133);
        obj c[0];
        assert (ARRAY_LEN(c) == 0);
        obj d[9999];
        assert (ARRAY_LEN(d) == 9999);
    }



    cout << "\nbefore removal (size = " << vec.size()
         << ")..."<<endl<<endl;
    {
        static const int arr[] = {1,2,3,4,5,2};
        assert (vec.size() == ARRAY_LEN(arr));
        for (uint32_t i = 0; i < ARRAY_LEN(arr); ++i) {
            assert (arr[i] == vec[i]->getval());
        }
        vector<shared_ptr<obj> >::const_iterator it = vec.begin();
        for (uint32_t i = 0; it != vec.end(); ++it, ++i) {
            assert (arr[i] == (*it)->getval());
        }
    }
    shared_ptr<obj> target = make_shared<obj>(2);

    assert (!Common::inVector(vec, target));
    assert (Common::isValueInVectorOfPtrs(vec, target));

//    cout << "done testing search\n";
    
    vec.erase(
        std::remove(vec.begin(), vec.end(), target), vec.end());
    cout << "\nafter vec.erase(std::remove(...)) removal (size = "
         << vec.size() << ")..."<<endl<<endl;
    {
        static const int arr[] = {1,2,3,4,5,2};
        assert (vec.size() == ARRAY_LEN(arr));
        for (uint32_t i = 0; i < ARRAY_LEN(arr); ++i) {
            assert (arr[i] == vec[i]->getval());
        }
        vector<shared_ptr<obj> >::const_iterator it = vec.begin();
        for (uint32_t i = 0; it != vec.end(); ++it, ++i) {
            assert (arr[i] == (*it)->getval());
        }
    }

    cout << "\ntry removeFromVector()..."<<endl;
    // this should not work, because we are comparing the pointers,
    // and not calling the operator==
    Common::removeFromVector(vec, target);
    cout << "  result: size = " << vec.size()
         << ")..."<<endl<<endl;
    {
        static const int arr[] = {1,2,3,4,5,2};
        assert (vec.size() == ARRAY_LEN(arr));
        for (uint32_t i = 0; i < ARRAY_LEN(arr); ++i) {
            assert (arr[i] == vec[i]->getval());
        }
        vector<shared_ptr<obj> >::const_iterator it = vec.begin();
        for (uint32_t i = 0; it != vec.end(); ++it, ++i) {
            assert (arr[i] == (*it)->getval());
        }
    }

    cout << "\ntry removeFromVectorOfPtrs()..."<<endl;
    Common::removeFromVectorOfPtrs(vec, target);
    cout << "  result: size = " << vec.size()
         << ")..."<<endl<<endl;
    {
        static const int arr[] = {1,3,4,5,2};
        assert (vec.size() == ARRAY_LEN(arr));
        for (uint32_t i = 0; i < ARRAY_LEN(arr); ++i) {
            assert (arr[i] == vec[i]->getval());
        }
        vector<shared_ptr<obj> >::const_iterator it = vec.begin();
        for (uint32_t i = 0; it != vec.end(); ++it, ++i) {
            assert (arr[i] == (*it)->getval());
        }
    }

    vec.insert(vec.begin()+1, b);
    {
        static const int arr[] = {1,2,3,4,5,2};
        assert (vec.size() == ARRAY_LEN(arr));
        for (uint32_t i = 0; i < ARRAY_LEN(arr); ++i) {
            assert (arr[i] == vec[i]->getval());
        }
        vector<shared_ptr<obj> >::const_iterator it = vec.begin();
        for (uint32_t i = 0; it != vec.end(); ++it, ++i) {
            assert (arr[i] == (*it)->getval());
        }
    }

    cout << "\ntry removeFromVectorOfPtrs() again..."<<endl;
    Common::removeFromVectorOfPtrs(vec, target, false);
    cout << "  result: size = " << vec.size()
         << ")..."<<endl<<endl;
    {
        static const int arr[] = {1,3,4,5};
        assert (vec.size() == ARRAY_LEN(arr));
        for (uint32_t i = 0; i < ARRAY_LEN(arr); ++i) {
            assert (arr[i] == vec[i]->getval());
        }
        vector<shared_ptr<obj> >::const_iterator it = vec.begin();
        for (uint32_t i = 0; it != vec.end(); ++it, ++i) {
            assert (arr[i] == (*it)->getval());
        }
    }
    cout << __func__ << "() ok" << endl;
    return 0;
}

int
testremoveFromVector()
{
    vector<string> vec;
    vec.push_back("1");
    vec.push_back("3");
    vec.push_back("2");
    vec.push_back("8");
    vec.push_back("5");

    Common::removeFromVector(vec, string("0"));
    {
        static const string arr[] = {"1","3","2","8","5"};
        assert (vec.size() == ARRAY_LEN(arr));
        for (uint32_t i = 0; i < ARRAY_LEN(arr); ++i) {
            assert (arr[i] == vec[i]);
        }
        vector<string>::const_iterator it = vec.begin();
        for (uint32_t i = 0; it != vec.end(); ++it, ++i) {
            assert (arr[i] == *it);
        }
    }

    Common::removeFromVector(vec, string("5"));
    {
        static const string arr[] = {"1","3","2","8"};
        assert (vec.size() == ARRAY_LEN(arr));
        for (uint32_t i = 0; i < ARRAY_LEN(arr); ++i) {
            assert (arr[i] == vec[i]);
        }
        vector<string>::const_iterator it = vec.begin();
        for (uint32_t i = 0; it != vec.end(); ++it, ++i) {
            assert (arr[i] == *it);
        }
    }

    Common::removeFromVector(vec, string("3"));
    {
        static const string arr[] = {"1","2","8"};
        assert (vec.size() == ARRAY_LEN(arr));
        for (uint32_t i = 0; i < ARRAY_LEN(arr); ++i) {
            assert (arr[i] == vec[i]);
        }
        vector<string>::const_iterator it = vec.begin();
        for (uint32_t i = 0; it != vec.end(); ++it, ++i) {
            assert (arr[i] == *it);
        }
    }

    Common::removeFromVector(vec, string("1"));
    {
        static const string arr[] = {"2","8"};
        assert (vec.size() == ARRAY_LEN(arr));
        for (uint32_t i = 0; i < ARRAY_LEN(arr); ++i) {
            assert (arr[i] == vec[i]);
        }
        vector<string>::const_iterator it = vec.begin();
        for (uint32_t i = 0; it != vec.end(); ++it, ++i) {
            assert (arr[i] == *it);
        }
    }

    Common::removeFromVector(vec, string("2"));
    Common::removeFromVector(vec, string("8"));
    {
        static const string arr[] = {};
        assert (vec.size() == ARRAY_LEN(arr));
        for (uint32_t i = 0; i < ARRAY_LEN(arr); ++i) {
            assert (arr[i] == vec[i]);
        }
    }

    cout << __func__ << "() ok" << endl;
    return 0;
}

int main()
{
    testRemoveVectorOfPtrs();
    testremoveFromVector();
    return 0;
}
