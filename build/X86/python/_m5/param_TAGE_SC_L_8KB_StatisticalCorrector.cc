/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/sim_object_param_struct_cc.py:295
 */

#include "pybind11/pybind11.h"
#include "pybind11/stl.h"

#include <type_traits>

#include "base/compiler.hh"
#include "params/TAGE_SC_L_8KB_StatisticalCorrector.hh"
#include "sim/init.hh"
#include "sim/sim_object.hh"

#include "cpu/pred/tage_sc_l_8KB.hh"

#include <vector>
#include "base/types.hh"
#include "base/types.hh"
#include "base/types.hh"
namespace py = pybind11;

namespace gem5
{

static void
module_init(py::module_ &m_internal)
{
py::module_ m = m_internal.def_submodule("param_TAGE_SC_L_8KB_StatisticalCorrector");
    py::class_<TAGE_SC_L_8KB_StatisticalCorrectorParams, StatisticalCorrectorParams, std::unique_ptr<TAGE_SC_L_8KB_StatisticalCorrectorParams, py::nodelete>>(m, "TAGE_SC_L_8KB_StatisticalCorrectorParams")
        .def(py::init<>())
        .def("create", &TAGE_SC_L_8KB_StatisticalCorrectorParams::create)
        .def_readwrite("gm", &TAGE_SC_L_8KB_StatisticalCorrectorParams::gm)
        .def_readwrite("gnb", &TAGE_SC_L_8KB_StatisticalCorrectorParams::gnb)
        .def_readwrite("logGnb", &TAGE_SC_L_8KB_StatisticalCorrectorParams::logGnb)
        ;

    py::class_<gem5::branch_prediction::TAGE_SC_L_8KB_StatisticalCorrector, gem5::branch_prediction::StatisticalCorrector, std::unique_ptr<gem5::branch_prediction::TAGE_SC_L_8KB_StatisticalCorrector, py::nodelete>>(m, "gem5_COLONS_branch_prediction_COLONS_TAGE_SC_L_8KB_StatisticalCorrector")
        ;

}

static EmbeddedPyBind embed_obj("TAGE_SC_L_8KB_StatisticalCorrector", module_init, "StatisticalCorrector");

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
class DummyTAGE_SC_L_8KB_StatisticalCorrectorParamsClass
{
  public:
    gem5::branch_prediction::TAGE_SC_L_8KB_StatisticalCorrector *create() const;
};

template <class CxxClass, class Enable=void>
class DummyTAGE_SC_L_8KB_StatisticalCorrectorShunt;

/*
 * This version directs to the real Params struct and the
 * default behavior of create if there's an appropriate
 * constructor.
 */
template <class CxxClass>
class DummyTAGE_SC_L_8KB_StatisticalCorrectorShunt<CxxClass, std::enable_if_t<
    std::is_constructible_v<CxxClass, const TAGE_SC_L_8KB_StatisticalCorrectorParams &>>>
{
  public:
    using Params = TAGE_SC_L_8KB_StatisticalCorrectorParams;
    static gem5::branch_prediction::TAGE_SC_L_8KB_StatisticalCorrector *
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
class DummyTAGE_SC_L_8KB_StatisticalCorrectorShunt<CxxClass, std::enable_if_t<
    !std::is_constructible_v<CxxClass, const TAGE_SC_L_8KB_StatisticalCorrectorParams &>>>
{
  public:
    using Params = DummyTAGE_SC_L_8KB_StatisticalCorrectorParamsClass;
    static gem5::branch_prediction::TAGE_SC_L_8KB_StatisticalCorrector *
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
[[maybe_unused]] gem5::branch_prediction::TAGE_SC_L_8KB_StatisticalCorrector *
DummyTAGE_SC_L_8KB_StatisticalCorrectorShunt<gem5::branch_prediction::TAGE_SC_L_8KB_StatisticalCorrector>::Params::create() const
{
    return DummyTAGE_SC_L_8KB_StatisticalCorrectorShunt<gem5::branch_prediction::TAGE_SC_L_8KB_StatisticalCorrector>::create(*this);
}

} // namespace gem5
