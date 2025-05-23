/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   /Users/dishagundecha/Desktop/SecureMemoryTutorial/src/mem/slicc/symbols/Type.py:935
 */

#include <cassert>
#include <iostream>
#include <string>

#include "base/logging.hh"
#include "mem/ruby/protocol/CacheRequestType.hh"

namespace gem5
{

namespace ruby
{

// Code for output operator
::std::ostream&
operator<<(::std::ostream& out, const CacheRequestType& obj)
{
    out << CacheRequestType_to_string(obj);
    out << ::std::flush;
    return out;
}

// Code to convert state to a string
std::string
CacheRequestType_to_string(const CacheRequestType& obj)
{
    switch(obj) {
      case CacheRequestType_DataArrayRead:
        return "DataArrayRead";
      case CacheRequestType_DataArrayWrite:
        return "DataArrayWrite";
      case CacheRequestType_TagArrayRead:
        return "TagArrayRead";
      case CacheRequestType_TagArrayWrite:
        return "TagArrayWrite";
      case CacheRequestType_AtomicALUOperation:
        return "AtomicALUOperation";
      default:
        panic("Invalid range for type CacheRequestType");
    }
    // Appease the compiler since this function has a return value
    return "";
}

// Code to convert from a string to the enumeration
CacheRequestType
string_to_CacheRequestType(const std::string& str)
{
    if (str == "DataArrayRead") {
        return CacheRequestType_DataArrayRead;
    } else if (str == "DataArrayWrite") {
        return CacheRequestType_DataArrayWrite;
    } else if (str == "TagArrayRead") {
        return CacheRequestType_TagArrayRead;
    } else if (str == "TagArrayWrite") {
        return CacheRequestType_TagArrayWrite;
    } else if (str == "AtomicALUOperation") {
        return CacheRequestType_AtomicALUOperation;
    } else {
        panic("Invalid string conversion for %s, type CacheRequestType", str);
    }
}

// Code to increment an enumeration type
CacheRequestType&
operator++(CacheRequestType& e)
{
    assert(e < CacheRequestType_NUM);
    return e = CacheRequestType(e+1);
}
} // namespace ruby
} // namespace gem5
