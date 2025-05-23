/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   /Users/dishagundecha/Desktop/SecureMemoryTutorial/src/mem/slicc/symbols/Type.py:935
 */

#include <cassert>
#include <iostream>
#include <string>

#include "base/logging.hh"
#include "mem/ruby/protocol/L1Cache_State.hh"

namespace gem5
{

namespace ruby
{

// Code to convert the current state to an access permission
AccessPermission L1Cache_State_to_permission(const L1Cache_State& obj)
{
    switch(obj) {
      case L1Cache_State_NP:
        return AccessPermission_Invalid;
      case L1Cache_State_I:
        return AccessPermission_Invalid;
      case L1Cache_State_S:
        return AccessPermission_Read_Only;
      case L1Cache_State_E:
        return AccessPermission_Read_Only;
      case L1Cache_State_M:
        return AccessPermission_Read_Write;
      case L1Cache_State_IS:
        return AccessPermission_Busy;
      case L1Cache_State_IM:
        return AccessPermission_Busy;
      case L1Cache_State_SM:
        return AccessPermission_Read_Only;
      case L1Cache_State_IS_I:
        return AccessPermission_Busy;
      case L1Cache_State_M_I:
        return AccessPermission_Busy;
      case L1Cache_State_SINK_WB_ACK:
        return AccessPermission_Busy;
      case L1Cache_State_PF_IS:
        return AccessPermission_Busy;
      case L1Cache_State_PF_IM:
        return AccessPermission_Busy;
      case L1Cache_State_PF_SM:
        return AccessPermission_Busy;
      case L1Cache_State_PF_IS_I:
        return AccessPermission_Busy;
      default:
        panic("Unknown state access permission converstion for L1Cache_State");
    }
    // Appease the compiler since this function has a return value
    return AccessPermission_Invalid;
}

} // namespace ruby
} // namespace gem5

namespace gem5
{

namespace ruby
{

// Code for output operator
::std::ostream&
operator<<(::std::ostream& out, const L1Cache_State& obj)
{
    out << L1Cache_State_to_string(obj);
    out << ::std::flush;
    return out;
}

// Code to convert state to a string
std::string
L1Cache_State_to_string(const L1Cache_State& obj)
{
    switch(obj) {
      case L1Cache_State_NP:
        return "NP";
      case L1Cache_State_I:
        return "I";
      case L1Cache_State_S:
        return "S";
      case L1Cache_State_E:
        return "E";
      case L1Cache_State_M:
        return "M";
      case L1Cache_State_IS:
        return "IS";
      case L1Cache_State_IM:
        return "IM";
      case L1Cache_State_SM:
        return "SM";
      case L1Cache_State_IS_I:
        return "IS_I";
      case L1Cache_State_M_I:
        return "M_I";
      case L1Cache_State_SINK_WB_ACK:
        return "SINK_WB_ACK";
      case L1Cache_State_PF_IS:
        return "PF_IS";
      case L1Cache_State_PF_IM:
        return "PF_IM";
      case L1Cache_State_PF_SM:
        return "PF_SM";
      case L1Cache_State_PF_IS_I:
        return "PF_IS_I";
      default:
        panic("Invalid range for type L1Cache_State");
    }
    // Appease the compiler since this function has a return value
    return "";
}

// Code to convert from a string to the enumeration
L1Cache_State
string_to_L1Cache_State(const std::string& str)
{
    if (str == "NP") {
        return L1Cache_State_NP;
    } else if (str == "I") {
        return L1Cache_State_I;
    } else if (str == "S") {
        return L1Cache_State_S;
    } else if (str == "E") {
        return L1Cache_State_E;
    } else if (str == "M") {
        return L1Cache_State_M;
    } else if (str == "IS") {
        return L1Cache_State_IS;
    } else if (str == "IM") {
        return L1Cache_State_IM;
    } else if (str == "SM") {
        return L1Cache_State_SM;
    } else if (str == "IS_I") {
        return L1Cache_State_IS_I;
    } else if (str == "M_I") {
        return L1Cache_State_M_I;
    } else if (str == "SINK_WB_ACK") {
        return L1Cache_State_SINK_WB_ACK;
    } else if (str == "PF_IS") {
        return L1Cache_State_PF_IS;
    } else if (str == "PF_IM") {
        return L1Cache_State_PF_IM;
    } else if (str == "PF_SM") {
        return L1Cache_State_PF_SM;
    } else if (str == "PF_IS_I") {
        return L1Cache_State_PF_IS_I;
    } else {
        panic("Invalid string conversion for %s, type L1Cache_State", str);
    }
}

// Code to increment an enumeration type
L1Cache_State&
operator++(L1Cache_State& e)
{
    assert(e < L1Cache_State_NUM);
    return e = L1Cache_State(e+1);
}
} // namespace ruby
} // namespace gem5
