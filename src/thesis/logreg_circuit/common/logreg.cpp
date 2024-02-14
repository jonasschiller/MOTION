

#include "logreg.h"

#include "algorithm/algorithm_description.h"
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/config.h"

encrypto::motion::RunTimeStatistics EvaluateProtocol(encrypto::motion::PartyPointer &party,
                                                     std::size_t number_of_simd,
                                                     encrypto::motion::MpcProtocol protocol)
{

  // TODO load the correct input format for the circuit both inputs are connected together as one long BitVector of required length

  std::vector<encrypto::motion::BitVector<>> tmp(35520,
                                                 encrypto::motion::BitVector<>(number_of_simd));
  encrypto::motion::ShareWrapper input{
      protocol == encrypto::motion::MpcProtocol::kBooleanGmw
          ? party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(tmp, 0)
          : party->In<encrypto::motion::MpcProtocol::kBmr>(tmp, 0)};
  for (int i = 0; i < 100; i++)
  {
    const auto kPathToAlgorithm{std::string(encrypto::motion::kRootDir) +
                                "/circuits/thesis/logreg.bristol"};
    const auto logreg_algorithm{encrypto::motion::AlgorithmDescription::FromBristol(kPathToAlgorithm)};
    const auto result{input.Evaluate(aes_algorithm)};
  }
  encrypto::motion::ShareWrapper output;
  if (check)
  {
    output = result.Out();
  }
  party->Run();
  party->Finish();
  const auto &statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}
