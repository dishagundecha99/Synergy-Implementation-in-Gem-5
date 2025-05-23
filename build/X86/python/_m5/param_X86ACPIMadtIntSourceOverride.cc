/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/sim_object_param_struct_cc.py:295
 */

#include "pybind11/pybind11.h"
#include "pybind11/stl.h"

#include <type_traits>

#include "base/compiler.hh"
#include "params/X86ACPIMadtIntSourceOverride.hh"
#include "sim/init.hh"
#include "sim/sim_object.hh"

#include "arch/x86/bios/acpi.hh"

#include "base/types.hh"
#include "base/types.hh"
#include "base/types.hh"
#include "base/types.hh"
namespace py = pybind11;

namespace gem5
{

static void
module_init(py::module_ &m_internal)
{
py::module_ m = m_internal.def_submodule("param_X86ACPIMadtIntSourceOverride");
    py::class_<X86ACPIMadtIntSourceOverrideParams, X86ACPIMadtRecordParams, std::unique_ptr<X86ACPIMadtIntSourceOverrideParams, py::nodelete>>(m, "X86ACPIMadtIntSourceOverrideParams")
        .def(py::init<>())
        .def("create", &X86ACPIMadtIntSourceOverrideParams::create)
        .def_readwrite("bus_source", &X86ACPIMadtIntSourceOverrideParams::bus_source)
        .def_readwrite("flags", &X86ACPIMadtIntSourceOverrideParams::flags)
        .def_readwrite("irq_source", &X86ACPIMadtIntSourceOverrideParams::irq_source)
        .def_readwrite("sys_int", &X86ACPIMadtIntSourceOverrideParams::sys_int)
        ;

    py::class_<gem5::X86ISA::ACPI::MADT::IntSourceOverride, gem5::X86ISA::ACPI::MADT::Record, std::unique_ptr<gem5::X86ISA::ACPI::MADT::IntSourceOverride, py::nodelete>>(m, "gem5_COLONS_X86ISA_COLONS_ACPI_COLONS_MADT_COLONS_IntSourceOverride")
        ;

}

static EmbeddedPyBind embed_obj("X86ACPIMadtIntSourceOverride", module_init, "X86ACPIMadtRecord");

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
class DummyX86ACPIMadtIntSourceOverrideParamsClass
{
  public:
    gem5::X86ISA::ACPI::MADT::IntSourceOverride *create() const;
};

template <class CxxClass, class Enable=void>
class DummyX86ACPIMadtIntSourceOverrideShunt;

/*
 * This version directs to the real Params struct and the
 * default behavior of create if there's an appropriate
 * constructor.
 */
template <class CxxClass>
class DummyX86ACPIMadtIntSourceOverrideShunt<CxxClass, std::enable_if_t<
    std::is_constructible_v<CxxClass, const X86ACPIMadtIntSourceOverrideParams &>>>
{
  public:
    using Params = X86ACPIMadtIntSourceOverrideParams;
    static gem5::X86ISA::ACPI::MADT::IntSourceOverride *
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
class DummyX86ACPIMadtIntSourceOverrideShunt<CxxClass, std::enable_if_t<
    !std::is_constructible_v<CxxClass, const X86ACPIMadtIntSourceOverrideParams &>>>
{
  public:
    using Params = DummyX86ACPIMadtIntSourceOverrideParamsClass;
    static gem5::X86ISA::ACPI::MADT::IntSourceOverride *
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
[[maybe_unused]] gem5::X86ISA::ACPI::MADT::IntSourceOverride *
DummyX86ACPIMadtIntSourceOverrideShunt<gem5::X86ISA::ACPI::MADT::IntSourceOverride>::Params::create() const
{
    return DummyX86ACPIMadtIntSourceOverrideShunt<gem5::X86ISA::ACPI::MADT::IntSourceOverride>::create(*this);
}

} // namespace gem5
