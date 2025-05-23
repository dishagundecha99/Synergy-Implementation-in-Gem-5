/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/sim_object_param_struct_cc.py:295
 */

#include "pybind11/pybind11.h"
#include "pybind11/stl.h"

#include <type_traits>

#include "base/compiler.hh"
#include "params/PciMemBar.hh"
#include "sim/init.hh"
#include "sim/sim_object.hh"

#include "dev/pci/device.hh"

#include "base/types.hh"
namespace py = pybind11;

namespace gem5
{

static void
module_init(py::module_ &m_internal)
{
py::module_ m = m_internal.def_submodule("param_PciMemBar");
    py::class_<PciMemBarParams, PciBarParams, std::unique_ptr<PciMemBarParams, py::nodelete>>(m, "PciMemBarParams")
        .def(py::init<>())
        .def("create", &PciMemBarParams::create)
        .def_readwrite("size", &PciMemBarParams::size)
        ;

    py::class_<gem5::PciMemBar, gem5::PciBar, std::unique_ptr<gem5::PciMemBar, py::nodelete>>(m, "gem5_COLONS_PciMemBar")
        ;

}

static EmbeddedPyBind embed_obj("PciMemBar", module_init, "PciBar");

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
class DummyPciMemBarParamsClass
{
  public:
    gem5::PciMemBar *create() const;
};

template <class CxxClass, class Enable=void>
class DummyPciMemBarShunt;

/*
 * This version directs to the real Params struct and the
 * default behavior of create if there's an appropriate
 * constructor.
 */
template <class CxxClass>
class DummyPciMemBarShunt<CxxClass, std::enable_if_t<
    std::is_constructible_v<CxxClass, const PciMemBarParams &>>>
{
  public:
    using Params = PciMemBarParams;
    static gem5::PciMemBar *
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
class DummyPciMemBarShunt<CxxClass, std::enable_if_t<
    !std::is_constructible_v<CxxClass, const PciMemBarParams &>>>
{
  public:
    using Params = DummyPciMemBarParamsClass;
    static gem5::PciMemBar *
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
[[maybe_unused]] gem5::PciMemBar *
DummyPciMemBarShunt<gem5::PciMemBar>::Params::create() const
{
    return DummyPciMemBarShunt<gem5::PciMemBar>::create(*this);
}

} // namespace gem5
