/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/sim_object_param_struct_cc.py:295
 */

#include "pybind11/pybind11.h"
#include "pybind11/stl.h"

#include <type_traits>

#include "base/compiler.hh"
#include "params/TreePLRURP.hh"
#include "sim/init.hh"
#include "sim/sim_object.hh"

#include "mem/cache/replacement_policies/tree_plru_rp.hh"

#include "base/types.hh"
namespace py = pybind11;

namespace gem5
{

static void
module_init(py::module_ &m_internal)
{
py::module_ m = m_internal.def_submodule("param_TreePLRURP");
    py::class_<TreePLRURPParams, BaseReplacementPolicyParams, std::unique_ptr<TreePLRURPParams, py::nodelete>>(m, "TreePLRURPParams")
        .def(py::init<>())
        .def("create", &TreePLRURPParams::create)
        .def_readwrite("num_leaves", &TreePLRURPParams::num_leaves)
        ;

    py::class_<gem5::replacement_policy::TreePLRU, gem5::replacement_policy::Base, std::unique_ptr<gem5::replacement_policy::TreePLRU, py::nodelete>>(m, "gem5_COLONS_replacement_policy_COLONS_TreePLRU")
        ;

}

static EmbeddedPyBind embed_obj("TreePLRURP", module_init, "BaseReplacementPolicy");

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
class DummyTreePLRURPParamsClass
{
  public:
    gem5::replacement_policy::TreePLRU *create() const;
};

template <class CxxClass, class Enable=void>
class DummyTreePLRURPShunt;

/*
 * This version directs to the real Params struct and the
 * default behavior of create if there's an appropriate
 * constructor.
 */
template <class CxxClass>
class DummyTreePLRURPShunt<CxxClass, std::enable_if_t<
    std::is_constructible_v<CxxClass, const TreePLRURPParams &>>>
{
  public:
    using Params = TreePLRURPParams;
    static gem5::replacement_policy::TreePLRU *
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
class DummyTreePLRURPShunt<CxxClass, std::enable_if_t<
    !std::is_constructible_v<CxxClass, const TreePLRURPParams &>>>
{
  public:
    using Params = DummyTreePLRURPParamsClass;
    static gem5::replacement_policy::TreePLRU *
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
[[maybe_unused]] gem5::replacement_policy::TreePLRU *
DummyTreePLRURPShunt<gem5::replacement_policy::TreePLRU>::Params::create() const
{
    return DummyTreePLRURPShunt<gem5::replacement_policy::TreePLRU>::create(*this);
}

} // namespace gem5
