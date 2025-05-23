/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   /Users/dishagundecha/Desktop/SecureMemoryTutorial/src/mem/slicc/symbols/Type.py:935
 */

#include <cassert>
#include <iostream>
#include <string>

#include "base/logging.hh"
#include "mem/ruby/protocol/SequencerStatus.hh"

namespace gem5
{

namespace ruby
{

// Code for output operator
::std::ostream&
operator<<(::std::ostream& out, const SequencerStatus& obj)
{
    out << SequencerStatus_to_string(obj);
    out << ::std::flush;
    return out;
}

// Code to convert state to a string
std::string
SequencerStatus_to_string(const SequencerStatus& obj)
{
    switch(obj) {
      case SequencerStatus_Idle:
        return "Idle";
      case SequencerStatus_Pending:
        return "Pending";
      default:
        panic("Invalid range for type SequencerStatus");
    }
    // Appease the compiler since this function has a return value
    return "";
}

// Code to convert from a string to the enumeration
SequencerStatus
string_to_SequencerStatus(const std::string& str)
{
    if (str == "Idle") {
        return SequencerStatus_Idle;
    } else if (str == "Pending") {
        return SequencerStatus_Pending;
    } else {
        panic("Invalid string conversion for %s, type SequencerStatus", str);
    }
}

// Code to increment an enumeration type
SequencerStatus&
operator++(SequencerStatus& e)
{
    assert(e < SequencerStatus_NUM);
    return e = SequencerStatus(e+1);
}
} // namespace ruby
} // namespace gem5
