#include "reveal.h"

#include "algorithm/algorithm_description.h"
#include "base/backend.h"
#include "base/register.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_share.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "secure_type/secure_unsigned_integer.h"
#include "utility/block.h"
#include "utility/config.h"

template <typename T>
encrypto::motion::ShareWrapper DummyArithmeticGmwShare(encrypto::motion::PartyPointer &party,
                                                       std::size_t bit_size,
                                                       std::size_t number_of_simd)
{
  std::vector<encrypto::motion::WirePointer> wires(1);
  const std::vector<T> dummy_input(number_of_simd, 0);

  encrypto::motion::BackendPointer backend{party->GetBackend()};
  encrypto::motion::RegisterPointer register_pointer{backend->GetRegister()};

  wires[0] = register_pointer->EmplaceWire<encrypto::motion::proto::arithmetic_gmw::Wire<T>>(
      dummy_input, *backend);
  wires[0]->SetOnlineFinished();

  return encrypto::motion::ShareWrapper(
      std::make_shared<encrypto::motion::proto::arithmetic_gmw::Share<T>>(wires));
}

encrypto::motion::ShareWrapper DummyBmrShare(encrypto::motion::PartyPointer &party,
                                             std::size_t number_of_wires,
                                             std::size_t number_of_simd)
{
  std::vector<encrypto::motion::WirePointer> wires(number_of_wires);
  const encrypto::motion::BitVector<> dummy_input(number_of_simd);

  encrypto::motion::BackendPointer backend{party->GetBackend()};
  encrypto::motion::RegisterPointer register_pointer{backend->GetRegister()};

  for (auto &w : wires)
  {
    auto bmr_wire{
        register_pointer->EmplaceWire<encrypto::motion::proto::bmr::Wire>(dummy_input, *backend)};
    w = bmr_wire;
    bmr_wire->GetMutablePublicKeys() = encrypto::motion::Block128Vector::MakeZero(
        backend->GetConfiguration()->GetNumOfParties() * number_of_simd);
    bmr_wire->GetMutableSecretKeys() = encrypto::motion::Block128Vector::MakeZero(number_of_simd);
    bmr_wire->GetMutablePermutationBits() = encrypto::motion::BitVector<>(number_of_simd);
    bmr_wire->SetSetupIsReady();
    bmr_wire->SetOnlineFinished();
  }

  return encrypto::motion::ShareWrapper(
      std::make_shared<encrypto::motion::proto::bmr::Share>(wires));
}

encrypto::motion::ShareWrapper DummyBooleanGmwShare(encrypto::motion::PartyPointer &party,
                                                    std::size_t number_of_wires,
                                                    std::size_t number_of_simd)
{
  std::vector<encrypto::motion::WirePointer> wires(number_of_wires);
  const encrypto::motion::BitVector<> dummy_input(number_of_simd);

  encrypto::motion::BackendPointer backend{party->GetBackend()};
  encrypto::motion::RegisterPointer register_pointer{backend->GetRegister()};

  for (auto &w : wires)
  {
    w = register_pointer->EmplaceWire<encrypto::motion::proto::boolean_gmw::Wire>(dummy_input,
                                                                                  *backend);
    w->SetOnlineFinished();
  }

  return encrypto::motion::ShareWrapper(
      std::make_shared<encrypto::motion::proto::boolean_gmw::Share>(wires));
}

encrypto::motion::RunTimeStatistics EvaluateProtocol(
    encrypto::motion::PartyPointer &party, std::size_t number_of_simd, std::size_t bit_size,
    encrypto::motion::MpcProtocol protocol)
{

  const std::vector<encrypto::motion::BitVector<>> temporary_bool(
      bit_size, encrypto::motion::BitVector<>(number_of_simd));
  const std::vector<std::uint32_t> temporary_int(number_of_simd, 0);
  encrypto::motion::ShareWrapper a;
  switch (protocol)
  {
  case encrypto::motion::MpcProtocol::kBooleanGmw:
    a = DummyBooleanGmwShare(party, bit_size, number_of_simd);
    break;
  case encrypto::motion::MpcProtocol::kArithmeticGmw:
    a = DummyArithmeticGmwShare<std::uint32_t>(party, bit_size, number_of_simd);
    break;
  case encrypto::motion::MpcProtocol::kBmr:
    a = DummyBmrShare(party, bit_size, number_of_simd);
    break;
  default:
    break;
  }
  a.Out();
  party->Run();
  party->Finish();
  const auto &statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}
