/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/sim_object_param_struct_cc.py:295
 */

#include "pybind11/pybind11.h"
#include "pybind11/stl.h"

#include <type_traits>

#include "base/compiler.hh"
#include "params/MinorFUTiming.hh"
#include "sim/init.hh"
#include "sim/sim_object.hh"

#include "cpu/minor/func_unit.hh"

#include <string>
#include "base/types.hh"
#include "base/types.hh"
#include "cpu/timing_expr.hh"
#include "base/types.hh"
#include "base/types.hh"
#include "cpu/minor/func_unit.hh"
#include <vector>
#include "base/types.hh"
namespace py = pybind11;

namespace gem5
{

static void
module_init(py::module_ &m_internal)
{
py::module_ m = m_internal.def_submodule("param_MinorFUTiming");
    py::class_<MinorFUTimingParams, SimObjectParams, std::unique_ptr<MinorFUTimingParams, py::nodelete>>(m, "MinorFUTimingParams")
        .def(py::init<>())
        .def("create", &MinorFUTimingParams::create)
        .def_readwrite("description", &MinorFUTimingParams::description)
        .def_readwrite("extraAssumedLat", &MinorFUTimingParams::extraAssumedLat)
        .def_readwrite("extraCommitLat", &MinorFUTimingParams::extraCommitLat)
        .def_readwrite("extraCommitLatExpr", &MinorFUTimingParams::extraCommitLatExpr)
        .def_readwrite("mask", &MinorFUTimingParams::mask)
        .def_readwrite("match", &MinorFUTimingParams::match)
        .def_readwrite("opClasses", &MinorFUTimingParams::opClasses)
        .def_readwrite("srcRegsRelativeLats", &MinorFUTimingParams::srcRegsRelativeLats)
        .def_readwrite("suppress", &MinorFUTimingParams::suppress)
        ;

    py::class_<gem5::MinorFUTiming, gem5::SimObject, std::unique_ptr<gem5::MinorFUTiming, py::nodelete>>(m, "gem5_COLONS_MinorFUTiming")
        ;

}

static EmbeddedPyBind embed_obj("MinorFUTiming", module_init, "SimObject");

} // namespace gem5
namespace gem5
{

namespace
{

/*
 * If we can't define a default create() method for this params
 * struct because the SimObject doesn't have the right
 * constructor, use template magic to make it so we're actually
 * defining a create method for this class instead.
 */
class DummyMinorFUTimingParamsClass
{
  public:
    gem5::MinorFUTiming *create() const;
};

template <class CxxClass, class Enable=void>
class DummyMinorFUTimingShunt;

/*
 * This version directs to the real Params struct and the
 * default behavior of create if there's an appropriate
 * constructor.
 */
template <class CxxClass>
class DummyMinorFUTimingShunt<CxxClass, std::enable_if_t<
    std::is_constructible_v<CxxClass, const MinorFUTimingParams &>>>
{
  public:
    using Params = MinorFUTimingParams;
    static gem5::MinorFUTiming *
    create(const Params &p)
    {
        return new CxxClass(p);
    }
};

/*
 * This version diverts to the DummyParamsClass and a dummy
 * implementation of create if the appropriate constructor does
 * not exist.
 */
template <class CxxClass>
class DummyMinorFUTimingShunt<CxxClass, std::enable_if_t<
    !std::is_constructible_v<CxxClass, const MinorFUTimingParams &>>>
{
  public:
    using Params = DummyMinorFUTimingParamsClass;
    static gem5::MinorFUTiming *
    create(const Params &p)
    {
        return nullptr;
    }
};

} // anonymous namespace

/*
 * An implementation of either the real Params struct's create
 * method, or the Dummy one. Either an implementation is
 * mandantory since this was shunted off to the dummy class, or
 * one is optional which will override this weak version.
 */
[[maybe_unused]] gem5::MinorFUTiming *
DummyMinorFUTimingShunt<gem5::MinorFUTiming>::Params::create() const
{
    return DummyMinorFUTimingShunt<gem5::MinorFUTiming>::create(*this);
}

} // namespace gem5
